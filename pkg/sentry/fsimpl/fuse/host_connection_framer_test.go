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
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// kernelSupervisorContext returns a fresh supervisor context, needed when
// issuing concurrent Calls (context.Blocker state is not goroutine-safe).
func kernelSupervisorContext(s *testutil.System) context.Context {
	return kernel.KernelFromContext(s.Ctx).SupervisorContext()
}

// These tests exercise the host-connection stream framer over a SOCK_STREAM
// socketpair, where message boundaries are not preserved and the framer must
// reassemble frames from the FUSE header's self-describing Len field.

// serverReadRequest reads one full FUSE request from serverFD and returns its
// header and payload bytes. FUSE requests in these tests are small enough to
// arrive in a single read.
func serverReadRequest(t *testing.T, serverFD int) (linux.FUSEHeaderIn, []byte) {
	t.Helper()
	buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	n, err := unix.Read(serverFD, buf)
	if err != nil {
		t.Errorf("serverReadRequest: %v", err)
		return linux.FUSEHeaderIn{}, nil
	}
	if n < int(linux.SizeOfFUSEHeaderIn) {
		t.Errorf("serverReadRequest: short read %d bytes", n)
		return linux.FUSEHeaderIn{}, nil
	}
	var hdr linux.FUSEHeaderIn
	hdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])
	payload := append([]byte(nil), buf[linux.SizeOfFUSEHeaderIn:n]...)
	return hdr, payload
}

type serverRequest struct {
	hdr     linux.FUSEHeaderIn
	payload []byte
}

// serverReadRequests reads exactly n FUSE requests from serverFD, deframing them
// from the byte stream by each request's self-describing Len. This is needed
// when multiple in-flight requests may coalesce into a single read.
func serverReadRequests(t *testing.T, serverFD int, n int) []serverRequest {
	t.Helper()
	var acc []byte
	scratch := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	var out []serverRequest
	for len(out) < n {
		for uint32(len(acc)) >= linux.SizeOfFUSEHeaderIn {
			var h linux.FUSEHeaderIn
			h.UnmarshalUnsafe(acc[:linux.SizeOfFUSEHeaderIn])
			if uint32(len(acc)) < h.Len {
				break
			}
			payload := append([]byte(nil), acc[linux.SizeOfFUSEHeaderIn:h.Len]...)
			out = append(out, serverRequest{hdr: h, payload: payload})
			acc = acc[h.Len:]
			if len(out) == n {
				return out
			}
		}
		r, err := unix.Read(serverFD, scratch)
		if err != nil {
			t.Errorf("serverReadRequests: %v", err)
			return out
		}
		if r == 0 {
			t.Errorf("serverReadRequests: unexpected EOF after %d requests", len(out))
			return out
		}
		acc = append(acc, scratch[:r]...)
	}
	return out
}

// buildReply constructs a complete FUSE reply frame (header + payload) with the
// header's Len set to the total frame length.
func buildReply(unique linux.FUSEOpID, errno int32, payload []byte) []byte {
	respLen := linux.SizeOfFUSEHeaderOut + uint32(len(payload))
	b := make([]byte, respLen)
	hdr := linux.FUSEHeaderOut{
		Len:    respLen,
		Error:  errno,
		Unique: unique,
	}
	hdr.MarshalUnsafe(b[:linux.SizeOfFUSEHeaderOut])
	copy(b[linux.SizeOfFUSEHeaderOut:], payload)
	return b
}

// buildRawHeader constructs a bare 16-byte FUSE reply header with an arbitrary
// Len, used to exercise invalid-length teardown.
func buildRawHeader(length uint32, unique linux.FUSEOpID) []byte {
	b := make([]byte, linux.SizeOfFUSEHeaderOut)
	hdr := linux.FUSEHeaderOut{Len: length, Unique: unique}
	hdr.MarshalUnsafe(b)
	return b
}

// writeChunks writes each chunk to fd as a separate sequence of write syscalls,
// letting a test control where read boundaries may fall on the peer.
func writeChunks(t *testing.T, fd int, chunks ...[]byte) {
	t.Helper()
	for _, c := range chunks {
		for len(c) > 0 {
			n, err := unix.Write(fd, c)
			if err != nil {
				t.Errorf("writeChunks: %v", err)
				return
			}
			c = c[n:]
		}
	}
}

type callResult struct {
	resp *Response
	err  error
}

// callWithTimeout issues hc.Call on a background goroutine and fails the test if
// it does not return within d. This prevents a framing regression from hanging
// the whole test binary.
func callWithTimeout(t *testing.T, hc *hostConnection, ctx context.Context, req *Request, d time.Duration) (*Response, error) {
	t.Helper()
	ch := make(chan callResult, 1)
	go func() {
		resp, err := hc.Call(ctx, req)
		ch <- callResult{resp, err}
	}()
	select {
	case res := <-ch:
		return res.resp, res.err
	case <-time.After(d):
		t.Fatalf("Call did not return within %v", d)
		return nil, nil
	}
}

// echoOnce reads one request and writes back the given reply chunks. Runs in a
// goroutine driven by the test.
func echoReplyChunks(t *testing.T, serverFD int, makeChunks func(hdr linux.FUSEHeaderIn, payload []byte) [][]byte) {
	hdr, payload := serverReadRequest(t, serverFD)
	writeChunks(t, serverFD, makeChunks(hdr, payload)...)
}

func TestHostFramerHeaderSplit(t *testing.T) {
	for k := 1; k < int(linux.SizeOfFUSEHeaderOut); k++ {
		t.Run(fmt.Sprintf("first-read-%d-bytes", k), func(t *testing.T) {
			s := setup(t)
			defer s.Destroy()
			hc, serverFD, cleanup := newTestHostConnectionType(t, unix.SOCK_STREAM)
			defer cleanup()

			creds := auth.CredentialsFromContext(s.Ctx)
			payload := primitive.Uint32(0xDEADBEEF)
			req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &payload)

			go echoReplyChunks(t, serverFD, func(h linux.FUSEHeaderIn, p []byte) [][]byte {
				reply := buildReply(h.Unique, 0, p)
				return [][]byte{reply[:k], reply[k:]}
			})

			resp, err := callWithTimeout(t, hc, s.Ctx, req, 5*time.Second)
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			var got primitive.Uint32
			if err := resp.UnmarshalPayload(&got); err != nil {
				t.Fatalf("UnmarshalPayload: %v", err)
			}
			if got != payload {
				t.Fatalf("payload: got %#x, want %#x", uint32(got), uint32(payload))
			}
		})
	}
}

func TestHostFramerPayloadSplit(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newTestHostConnectionType(t, unix.SOCK_STREAM)
	defer cleanup()

	creds := auth.CredentialsFromContext(s.Ctx)
	// Large-ish structured payload the client can verify.
	const nWords = 400
	zero := primitive.Uint32(0)
	req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &zero)

	go func() {
		hdr, _ := serverReadRequest(t, serverFD)
		payload := make([]byte, nWords*4)
		for i := 0; i < nWords; i++ {
			w := primitive.Uint32(i)
			w.MarshalUnsafe(payload[i*4 : i*4+4])
		}
		reply := buildReply(hdr.Unique, 0, payload)
		// Dribble the reply out in 5-byte writes.
		var chunks [][]byte
		for i := 0; i < len(reply); i += 5 {
			end := i + 5
			if end > len(reply) {
				end = len(reply)
			}
			chunks = append(chunks, reply[i:end])
		}
		writeChunks(t, serverFD, chunks...)
	}()

	resp, err := callWithTimeout(t, hc, s.Ctx, req, 5*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	data := resp.data[resp.hdr.SizeBytes():]
	if len(data) != nWords*4 {
		t.Fatalf("payload length: got %d, want %d", len(data), nWords*4)
	}
	for i := 0; i < nWords; i++ {
		var got primitive.Uint32
		got.UnmarshalUnsafe(data[i*4 : i*4+4])
		if uint32(got) != uint32(i) {
			t.Fatalf("word %d: got %d, want %d", i, uint32(got), i)
		}
	}
}

func TestHostFramerCoalescedReplies(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newTestHostConnectionType(t, unix.SOCK_STREAM)
	defer cleanup()

	creds := auth.CredentialsFromContext(s.Ctx)

	const n = 3
	// Server reads all n requests (deframing them robustly), then writes all n
	// replies back in a single coalesced write.
	go func() {
		reqs := serverReadRequests(t, serverFD, n)
		var blob []byte
		for _, rq := range reqs {
			blob = append(blob, buildReply(rq.hdr.Unique, 0, rq.payload)...)
		}
		writeChunks(t, serverFD, blob)
	}()

	// Issue all requests concurrently so they are all in flight before the
	// server replies.
	results := make(chan callResult, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			ctx := kernelSupervisorContext(s)
			p := primitive.Uint32(uint32(100 + i))
			req := hc.conn.NewRequest(creds, 1, uint64(i), echoTestOpcode, &p)
			resp, err := hc.Call(ctx, req)
			if err == nil {
				var got primitive.Uint32
				if uerr := resp.UnmarshalPayload(&got); uerr != nil {
					err = uerr
				} else if uint32(got) != uint32(100+i) {
					err = fmt.Errorf("payload got %d, want %d", uint32(got), 100+i)
				}
			}
			results <- callResult{resp, err}
		}(i)
	}
	for i := 0; i < n; i++ {
		select {
		case res := <-results:
			if res.err != nil {
				t.Errorf("Call: %v", res.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("coalesced replies: Call %d did not return", i)
		}
	}
}

func TestHostFramerReadaheadRemainder(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newTestHostConnectionType(t, unix.SOCK_STREAM)
	defer cleanup()

	creds := auth.CredentialsFromContext(s.Ctx)
	p1 := primitive.Uint32(11)
	r1 := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &p1)
	p2 := primitive.Uint32(22)
	r2 := hc.conn.NewRequest(creds, 1, 2, echoTestOpcode, &p2)

	go func() {
		// Both requests must be in flight before we can write both replies, so
		// read them robustly (they may coalesce into one read).
		reqs := serverReadRequests(t, serverFD, 2)
		replyA := buildReply(reqs[0].hdr.Unique, 0, reqs[0].payload)
		replyB := buildReply(reqs[1].hdr.Unique, 0, reqs[1].payload)
		blob := append(append([]byte(nil), replyA...), replyB...)
		// First write ends partway through the second reply, so the framer must
		// retain the read-ahead remainder for the next frame.
		splitAt := len(replyA) + 3
		writeChunks(t, serverFD, blob[:splitAt], blob[splitAt:])
	}()

	// Issue both requests concurrently.
	res1ch := make(chan callResult, 1)
	res2ch := make(chan callResult, 1)
	go func() {
		resp, err := hc.Call(kernelSupervisorContext(s), r1)
		res1ch <- callResult{resp, err}
	}()
	go func() {
		resp, err := hc.Call(kernelSupervisorContext(s), r2)
		res2ch <- callResult{resp, err}
	}()

	checkPayload := func(name string, ch chan callResult, want primitive.Uint32) {
		select {
		case res := <-ch:
			if res.err != nil {
				t.Errorf("%s Call: %v", name, res.err)
				return
			}
			var got primitive.Uint32
			if err := res.resp.UnmarshalPayload(&got); err != nil {
				t.Errorf("%s UnmarshalPayload: %v", name, err)
				return
			}
			if got != want {
				t.Errorf("%s payload: got %d, want %d", name, uint32(got), uint32(want))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s Call did not return", name)
		}
	}
	checkPayload("r1", res1ch, p1)
	checkPayload("r2", res2ch, p2)
}

func TestHostFramerNotificationDiscarded(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newTestHostConnectionType(t, unix.SOCK_STREAM)
	defer cleanup()

	creds := auth.CredentialsFromContext(s.Ctx)
	p := primitive.Uint32(77)
	req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &p)

	go func() {
		hdr, payload := serverReadRequest(t, serverFD)
		// A notification (Unique == 0) with a notify code in Error, then the real
		// reply. The notification is split across writes to exercise reassembly.
		notif := buildReply(0, 2 /* FUSE_NOTIFY_INVAL_INODE */, []byte("invalidate-me"))
		reply := buildReply(hdr.Unique, 0, payload)
		blob := append(append([]byte(nil), notif...), reply...)
		splitAt := len(notif) - 4
		writeChunks(t, serverFD, blob[:splitAt], blob[splitAt:])
	}()

	resp, err := callWithTimeout(t, hc, s.Ctx, req, 5*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var got primitive.Uint32
	if err := resp.UnmarshalPayload(&got); err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if got != p {
		t.Fatalf("payload: got %d, want %d", uint32(got), uint32(p))
	}
}

func TestHostFramerUnknownUniqueDropped(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newTestHostConnectionType(t, unix.SOCK_STREAM)
	defer cleanup()

	creds := auth.CredentialsFromContext(s.Ctx)
	p := primitive.Uint32(55)
	req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &p)

	go func() {
		hdr, payload := serverReadRequest(t, serverFD)
		// A reply for a request that was never issued, followed by the real one.
		stray := buildReply(hdr.Unique+1000, 0, []byte("stray"))
		reply := buildReply(hdr.Unique, 0, payload)
		writeChunks(t, serverFD, stray, reply)
	}()

	resp, err := callWithTimeout(t, hc, s.Ctx, req, 5*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var got primitive.Uint32
	if err := resp.UnmarshalPayload(&got); err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if got != p {
		t.Fatalf("payload: got %d, want %d", uint32(got), uint32(p))
	}
	// The stray reply must not have torn down the connection.
	hc.conn.mu.Lock()
	connected := hc.conn.connected
	hc.conn.mu.Unlock()
	if !connected {
		t.Fatal("connection unexpectedly disconnected after stray reply")
	}
}

func TestHostFramerLargeReply(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newTestHostConnectionType(t, unix.SOCK_STREAM)
	defer cleanup()
	// maxFrame is reply_buf_max, which defaults to 1 MiB in the test connection,
	// well above the old 8 KB cap.

	creds := auth.CredentialsFromContext(s.Ctx)
	zero := primitive.Uint32(0)
	req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &zero)

	const payloadLen = 100000 // >> FUSE_MIN_READ_BUFFER (8192)
	go func() {
		hdr, _ := serverReadRequest(t, serverFD)
		payload := make([]byte, payloadLen)
		for i := range payload {
			payload[i] = byte(i)
		}
		writeChunks(t, serverFD, buildReply(hdr.Unique, 0, payload))
	}()

	resp, err := callWithTimeout(t, hc, s.Ctx, req, 10*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	data := resp.data[resp.hdr.SizeBytes():]
	if len(data) != payloadLen {
		t.Fatalf("payload length: got %d, want %d", len(data), payloadLen)
	}
	for i := range data {
		if data[i] != byte(i) {
			t.Fatalf("payload byte %d: got %d, want %d", i, data[i], byte(i))
		}
	}
}

func TestHostFramerInvalidLenTearsDown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length uint32
	}{
		{"len-below-header", 8},
		{"len-above-maxframe", 2 << 20}, // > reply_buf_max (1 MiB) in the test conn.
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := setup(t)
			defer s.Destroy()
			hc, serverFD, cleanup := newTestHostConnectionType(t, unix.SOCK_STREAM)
			defer cleanup()

			creds := auth.CredentialsFromContext(s.Ctx)
			zero := primitive.Uint32(0)
			req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &zero)

			go func() {
				hdr, _ := serverReadRequest(t, serverFD)
				writeChunks(t, serverFD, buildRawHeader(tc.length, hdr.Unique))
			}()

			resp, err := callWithTimeout(t, hc, s.Ctx, req, 5*time.Second)
			// The pending caller must be released with an error, either as a
			// transport error or an ECONNABORTED FUSE error in the response.
			if err == nil {
				if resp == nil || !linuxerr.Equals(linuxerr.ECONNABORTED, resp.Error()) {
					t.Fatalf("expected ECONNABORTED, got resp=%v err=nil", resp)
				}
			}
			// The connection must be torn down; a subsequent call fails fast.
			zero2 := primitive.Uint32(0)
			req2 := hc.conn.NewRequest(creds, 1, 2, echoTestOpcode, &zero2)
			if _, err := hc.Call(s.Ctx, req2); err == nil {
				t.Fatal("expected error on call after teardown, got nil")
			}
		})
	}
}

func TestHostFramerInitStream(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	fsopts := filesystemOptions{
		maxActiveRequests: maxActiveRequestsDefault,
		maxRead:           4096,
	}
	conn, err := newFUSEConnectionOpts(&fsopts)
	if err != nil {
		t.Fatalf("newFUSEConnectionOpts: %v", err)
	}
	hc := newHostConnection(conn, int32(fds[0]))

	const testMaxWrite uint32 = 65536
	done := make(chan struct{})
	go func() {
		defer close(done)
		hdr, _ := serverReadRequest(t, fds[1])
		if hdr.Opcode != linux.FUSE_INIT {
			t.Errorf("expected FUSE_INIT, got %d", hdr.Opcode)
			return
		}
		initOut := linux.FUSEInitOut{
			Major:    linux.FUSE_KERNEL_VERSION,
			Minor:    linux.FUSE_KERNEL_MINOR_VERSION,
			MaxWrite: testMaxWrite,
		}
		payload := make([]byte, initOut.SizeBytes())
		initOut.MarshalUnsafe(payload)
		reply := buildReply(hdr.Unique, 0, payload)
		// Split the INIT reply to force the synchronous INIT path through the
		// stream framer rather than a single read.
		writeChunks(t, fds[1], reply[:10], reply[10:])
	}()

	creds := auth.CredentialsFromContext(s.Ctx)
	if err := hc.InitSend(creds, 1, true); err != nil {
		t.Fatalf("InitSend: %v", err)
	}
	<-done

	if !conn.isInitialized() {
		t.Fatal("connection not initialized after InitSend")
	}
	conn.mu.Lock()
	gotMaxWrite := conn.maxWrite
	conn.mu.Unlock()
	if gotMaxWrite != testMaxWrite {
		t.Errorf("maxWrite = %d, want %d", gotMaxWrite, testMaxWrite)
	}
}
