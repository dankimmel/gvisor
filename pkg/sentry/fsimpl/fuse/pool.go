// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fuse

import (
	"runtime"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// debugFUSEBuffers, when true, enables a finalizer-based detector for reply
// buffers that are garbage-collected without being released. With the constant
// false the compiler eliminates all of the finalizer machinery. Enable only for
// bring-up.
const debugFUSEBuffers = false

// bufClass identifies a reply-buffer size class.
type bufClass uint8

const (
	// bufClassSmall is the pooled 8 KB metadata-reply class.
	bufClassSmall bufClass = iota
	// bufClassLarge is the pooled, variable-capacity READ/READDIR-reply class,
	// gated by a counting semaphore.
	bufClassLarge
)

// smallBufSize is the size of a small-class reply buffer.
const smallBufSize = int(linux.FUSE_MIN_READ_BUFFER)

// largeBufChunk is the allocation granularity for large-class buffers: a large
// buffer's capacity is rounded up to a multiple of this (capped at the
// configured ceiling).
const largeBufChunk = 64 * 1024

// poisonByte is written over a released buffer under debugFUSEBuffers, so a
// use-after-release corrupts recognizably instead of silently returning stale
// data.
const poisonByte = 0x5a

// pooledBuf is a reply buffer drawn from a bufferPool. Ownership is single: the
// reader owns it until it either transfers it to a live future (whose opcode
// handler later releases it) or releases it itself. A missed release is a
// pool-miss (extra allocation) or, for the large class, a stuck gate permit —
// never a use-after-free.
type pooledBuf struct {
	bytes    []byte
	class    bufClass
	released bool
	pool     *bufferPool

	// acquireStack holds the stack at acquisition; populated only under
	// debugFUSEBuffers.
	acquireStack []byte
}

// bufferPool provides pooled, size-classed reply buffers for one host
// connection, plus a counting gate bounding the number of live large-class
// buffers. Acquire/release counters are exported for test assertions.
type bufferPool struct {
	smallPool sync.Pool
	largePool sync.Pool

	// largeGate is a counting semaphore (buffered channel) bounding live
	// large-class buffers; acquired before taking a large buffer and released
	// when it is released.
	largeGate chan struct{}

	// replyBufMax is the large-class capacity ceiling in bytes.
	replyBufMax int

	smallAcquired atomicbitops.Uint64
	smallReleased atomicbitops.Uint64
	largeAcquired atomicbitops.Uint64
	largeReleased atomicbitops.Uint64
}

// newBufferPool creates a bufferPool whose large class is capped at replyBufMax
// bytes and gated to at most replyBufConcurrency concurrent live buffers.
func newBufferPool(replyBufMax uint32, replyBufConcurrency uint32) *bufferPool {
	return &bufferPool{
		largeGate:   make(chan struct{}, replyBufConcurrency),
		replyBufMax: int(replyBufMax),
	}
}

// roundUpInt rounds n up to the next multiple of mult.
func roundUpInt(n, mult int) int {
	return (n + mult - 1) / mult * mult
}

// get returns a reply buffer of exactly need bytes. Requests up to the small
// class come from the small pool; larger requests acquire a large-class gate
// permit first (blocking to propagate backpressure to the backend) and come
// from the large pool.
func (bp *bufferPool) get(need int) *pooledBuf {
	if need <= smallBufSize {
		return bp.getSmall(need)
	}
	return bp.getLarge(need)
}

func (bp *bufferPool) getSmall(need int) *pooledBuf {
	pb, _ := bp.smallPool.Get().(*pooledBuf)
	if pb == nil {
		pb = &pooledBuf{bytes: make([]byte, smallBufSize), class: bufClassSmall}
	}
	pb.pool = bp
	pb.released = false
	pb.bytes = pb.bytes[:need]
	bp.smallAcquired.Add(1)
	bp.armFinalizer(pb)
	return pb
}

func (bp *bufferPool) getLarge(need int) *pooledBuf {
	// Block here if reply_buf_concurrency large buffers are already live. This
	// is intentional backpressure: the backend stalls (via the FD's socket
	// buffer) when the Sentry cannot absorb more large replies.
	bp.largeGate <- struct{}{}
	pb, _ := bp.largePool.Get().(*pooledBuf)
	if pb == nil || cap(pb.bytes) < need {
		size := roundUpInt(need, largeBufChunk)
		if size > bp.replyBufMax {
			size = bp.replyBufMax
		}
		if size < need {
			// need is bounded by maxFrame == replyBufMax, so this only guards
			// against a misconfiguration.
			size = need
		}
		pb = &pooledBuf{bytes: make([]byte, size), class: bufClassLarge}
	}
	pb.pool = bp
	pb.released = false
	pb.bytes = pb.bytes[:need]
	bp.largeAcquired.Add(1)
	bp.armFinalizer(pb)
	return pb
}

// release returns the buffer to its pool. It is idempotent: a second release is
// a no-op. For a large buffer it also releases the gate permit.
func (pb *pooledBuf) release() {
	if pb.released {
		return
	}
	pb.released = true
	bp := pb.pool
	pb.disarmFinalizer()
	pb.bytes = pb.bytes[:cap(pb.bytes)]
	if debugFUSEBuffers {
		// Poison the buffer so any read of an aliased payload after release
		// (e.g. a READ whose data was not copied out first) is caught.
		for i := range pb.bytes {
			pb.bytes[i] = poisonByte
		}
	}
	switch pb.class {
	case bufClassSmall:
		bp.smallReleased.Add(1)
		bp.smallPool.Put(pb)
	case bufClassLarge:
		bp.largeReleased.Add(1)
		bp.largePool.Put(pb)
		<-bp.largeGate
	}
}

// counts returns the per-class acquire/release counters, for tests.
func (bp *bufferPool) counts() (smallAcq, smallRel, largeAcq, largeRel uint64) {
	return bp.smallAcquired.Load(), bp.smallReleased.Load(), bp.largeAcquired.Load(), bp.largeReleased.Load()
}

// balanced reports whether every acquired buffer has been released and no gate
// permit is outstanding.
func (bp *bufferPool) balanced() bool {
	sa, sr, la, lr := bp.counts()
	return sa == sr && la == lr && len(bp.largeGate) == 0
}

// armFinalizer, under debugFUSEBuffers, stashes the acquire stack and sets a
// finalizer that fires if the buffer is GC'd without release. Compiled out when
// debugFUSEBuffers is false.
func (bp *bufferPool) armFinalizer(pb *pooledBuf) {
	if debugFUSEBuffers {
		pb.acquireStack = make([]byte, 4096)
		pb.acquireStack = pb.acquireStack[:runtime.Stack(pb.acquireStack, false)]
		runtime.SetFinalizer(pb, (*pooledBuf).finalize)
	}
}

// disarmFinalizer clears the finalizer before pooling, so a reused buffer does
// not fire a stale finalizer. Compiled out when debugFUSEBuffers is false.
func (pb *pooledBuf) disarmFinalizer() {
	if debugFUSEBuffers {
		runtime.SetFinalizer(pb, nil)
	}
}

// finalize is the debug-only missed-release detector. It logs loudly and, for a
// large buffer, releases the gate permit so a leaked buffer does not
// permanently ratchet down large-reply concurrency.
func (pb *pooledBuf) finalize() {
	if pb.released {
		return
	}
	log.Warningf("fuse: reply buffer (class %d) garbage-collected without Release; acquired at:\n%s", pb.class, pb.acquireStack)
	if pb.class == bufClassLarge {
		<-pb.pool.largeGate
	}
}
