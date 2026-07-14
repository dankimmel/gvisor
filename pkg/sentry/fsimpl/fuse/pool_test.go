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
	"sync"
	"testing"
	"time"
)

func TestBufferPoolSmallBalance(t *testing.T) {
	bp := newBufferPool(1<<20, 4)
	for i := 0; i < 100; i++ {
		pb := bp.get(100)
		if len(pb.bytes) != 100 {
			t.Fatalf("small buffer len = %d, want 100", len(pb.bytes))
		}
		if pb.class != bufClassSmall {
			t.Fatalf("class = %d, want small", pb.class)
		}
		pb.release()
	}
	if !bp.balanced() {
		sa, sr, la, lr := bp.counts()
		t.Errorf("counters not balanced: smallAcq=%d smallRel=%d largeAcq=%d largeRel=%d", sa, sr, la, lr)
	}
}

func TestBufferPoolLargeSizing(t *testing.T) {
	bp := newBufferPool(1<<20, 4)

	pb := bp.getLarge(100000)
	if pb.class != bufClassLarge {
		t.Fatalf("class = %d, want large", pb.class)
	}
	if len(pb.bytes) != 100000 {
		t.Errorf("len = %d, want 100000", len(pb.bytes))
	}
	if want := roundUpInt(100000, largeBufChunk); cap(pb.bytes) != want {
		t.Errorf("cap = %d, want %d (rounded to %d)", cap(pb.bytes), want, largeBufChunk)
	}
	pb.release()

	// A request at the ceiling must not exceed replyBufMax.
	pb2 := bp.getLarge(1 << 20)
	if cap(pb2.bytes) > 1<<20 {
		t.Errorf("cap = %d exceeds replyBufMax %d", cap(pb2.bytes), 1<<20)
	}
	pb2.release()

	if !bp.balanced() {
		t.Errorf("counters not balanced after large round-trips")
	}
}

func TestBufferPoolGateBlocksAndUnblocks(t *testing.T) {
	bp := newBufferPool(1<<20, 2)

	a := bp.getLarge(70000)
	b := bp.getLarge(70000)

	blocked := make(chan *pooledBuf, 1)
	go func() { blocked <- bp.getLarge(70000) }()

	select {
	case <-blocked:
		t.Fatal("third getLarge should have blocked while 2 large buffers are live")
	case <-time.After(100 * time.Millisecond):
	}

	// Releasing one live buffer must unblock the waiter.
	a.release()
	select {
	case c := <-blocked:
		c.release()
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not unblock after a large buffer was released")
	}
	b.release()

	if !bp.balanced() {
		t.Errorf("counters not balanced; gate len = %d", len(bp.largeGate))
	}
}

func TestBufferPoolReleaseIdempotent(t *testing.T) {
	bp := newBufferPool(1<<20, 1)
	pb := bp.getLarge(70000)
	pb.release()
	pb.release() // must be a no-op

	if _, _, _, lr := bp.counts(); lr != 1 {
		t.Errorf("largeReleased = %d after double release, want 1", lr)
	}

	// The single gate permit must be free (not double-released), so a fresh
	// acquire succeeds.
	got := make(chan *pooledBuf, 1)
	go func() { got <- bp.getLarge(70000) }()
	select {
	case c := <-got:
		c.release()
	case <-time.After(2 * time.Second):
		t.Fatal("gate permit accounting corrupted by double release")
	}
}

func TestBufferPoolLargeReuseCapacity(t *testing.T) {
	bp := newBufferPool(1<<20, 4)
	pb := bp.getLarge(200000)
	pb.release()
	// sync.Pool gives no reuse guarantee (GC may drain it), so only assert the
	// correctness property: a subsequent smaller request still yields cap >=
	// need and the requested length.
	pb2 := bp.getLarge(100000)
	if cap(pb2.bytes) < 100000 {
		t.Errorf("cap = %d, want >= 100000", cap(pb2.bytes))
	}
	if len(pb2.bytes) != 100000 {
		t.Errorf("len = %d, want 100000", len(pb2.bytes))
	}
	pb2.release()
	if !bp.balanced() {
		t.Errorf("counters not balanced after reuse")
	}
}

func TestBufferPoolStress(t *testing.T) {
	bp := newBufferPool(1<<20, 8)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				need := 100
				if i%3 == 0 {
					need = 70000
				}
				pb := bp.get(need)
				pb.release()
			}
		}()
	}
	wg.Wait()
	if !bp.balanced() {
		sa, sr, la, lr := bp.counts()
		t.Errorf("counters not balanced under load: smallAcq=%d smallRel=%d largeAcq=%d largeRel=%d gate=%d", sa, sr, la, lr, len(bp.largeGate))
	}
}
