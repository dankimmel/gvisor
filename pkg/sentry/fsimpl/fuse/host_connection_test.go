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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// newTestHostConnection creates a hostConnection backed by a socketpair.
// Returns the hostConnection, the server-side FD, and a cleanup function.
// The connection is pre-initialized and the reader goroutine is started.
func newTestHostConnection(t *testing.T) (*hostConnection, int, func()) {
	return newTestHostConnectionType(t, unix.SOCK_SEQPACKET)
}

// newTestHostConnectionType is like newTestHostConnection but allows choosing
// the socketpair type (e.g. SOCK_STREAM to exercise the stream framer).
func newTestHostConnectionType(t *testing.T, sockType int) (*hostConnection, int, func()) {
	t.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, sockType, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}

	fsopts := filesystemOptions{
		maxActiveRequests: maxActiveRequestsDefault,
		maxRead:           4096,
	}
	conn, err := newFUSEConnectionOpts(&fsopts)
	if err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		t.Fatalf("newFUSEConnectionOpts: %v", err)
	}

	conn.setInitialized()
	conn.mu.Lock()
	conn.connInitSuccess = true
	conn.maxWrite = 4096
	conn.mu.Unlock()

	hc := newHostConnection(conn, int32(fds[0]))
	conn.fuseConn = hc
	hc.startReader()

	cleanup := func() {
		unix.Shutdown(fds[1], unix.SHUT_RDWR)
		unix.Shutdown(fds[0], unix.SHUT_RDWR)
		unix.Close(fds[0])
		unix.Close(fds[1])
	}
	return hc, fds[1], cleanup
}

// echoServer reads one FUSE request from serverFD and echoes the payload
// back as a response. It signals completion on the done channel.
func echoServer(t *testing.T, serverFD int, done chan struct{}) {
	t.Helper()
	defer close(done)

	buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	n, err := unix.Read(serverFD, buf)
	if err != nil {
		t.Errorf("server Read: %v", err)
		return
	}
	if n < int(linux.SizeOfFUSEHeaderIn) {
		t.Errorf("server: short read %d bytes", n)
		return
	}

	var reqHdr linux.FUSEHeaderIn
	reqHdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])

	payload := buf[linux.SizeOfFUSEHeaderIn:n]
	respLen := linux.SizeOfFUSEHeaderOut + uint32(len(payload))
	respBuf := make([]byte, respLen)

	respHdr := linux.FUSEHeaderOut{
		Len:    respLen,
		Error:  0,
		Unique: reqHdr.Unique,
	}
	respHdr.MarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])
	copy(respBuf[linux.SizeOfFUSEHeaderOut:], payload)

	if _, err := unix.Write(serverFD, respBuf); err != nil {
		t.Errorf("server Write: %v", err)
	}
}

// echoServerN reads count FUSE requests from serverFD and echoes each
// payload back as a response. It signals completion on the done channel.
func echoServerN(t *testing.T, serverFD int, count int, done chan struct{}) {
	t.Helper()
	defer close(done)

	for i := 0; i < count; i++ {
		buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
		n, err := unix.Read(serverFD, buf)
		if err != nil {
			t.Errorf("server Read %d: %v", i, err)
			return
		}
		if n < int(linux.SizeOfFUSEHeaderIn) {
			t.Errorf("server: short read %d bytes on request %d", n, i)
			return
		}

		var reqHdr linux.FUSEHeaderIn
		reqHdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])

		payload := buf[linux.SizeOfFUSEHeaderIn:n]
		respLen := linux.SizeOfFUSEHeaderOut + uint32(len(payload))
		respBuf := make([]byte, respLen)

		respHdr := linux.FUSEHeaderOut{
			Len:    respLen,
			Error:  0,
			Unique: reqHdr.Unique,
		}
		respHdr.MarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])
		copy(respBuf[linux.SizeOfFUSEHeaderOut:], payload)

		if _, err := unix.Write(serverFD, respBuf); err != nil {
			t.Errorf("server Write %d: %v", i, err)
			return
		}
	}
}

func TestHostConnectionCall(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, serverFD, cleanup := newTestHostConnection(t)
	defer cleanup()

	done := make(chan struct{})
	go echoServer(t, serverFD, done)

	creds := auth.CredentialsFromContext(s.Ctx)
	testObj := primitive.Uint32(42)
	req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &testObj)

	resp, err := hc.Call(s.Ctx, req)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	<-done

	if resp.hdr.Error != 0 {
		t.Fatalf("response error: %d", resp.hdr.Error)
	}
	if resp.hdr.Unique != req.hdr.Unique {
		t.Fatalf("unique mismatch: got %d, want %d", resp.hdr.Unique, req.hdr.Unique)
	}

	var got primitive.Uint32
	if err := resp.UnmarshalPayload(&got); err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if got != testObj {
		t.Fatalf("payload: got %d, want %d", got, testObj)
	}
	resp.Release()

	if !hc.pool.balanced() {
		t.Errorf("buffer pool not balanced after Call+Release")
	}
}

func TestHostConnectionInit(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[1])
	defer unix.Close(fds[0])
	defer unix.Shutdown(fds[0], unix.SHUT_RDWR)
	defer unix.Shutdown(fds[1], unix.SHUT_RDWR)

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

		buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
		n, err := unix.Read(fds[1], buf)
		if err != nil {
			t.Errorf("server Read: %v", err)
			return
		}

		var reqHdr linux.FUSEHeaderIn
		reqHdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])
		if reqHdr.Opcode != linux.FUSE_INIT {
			t.Errorf("expected FUSE_INIT opcode, got %d", reqHdr.Opcode)
			return
		}
		_ = n

		initOut := linux.FUSEInitOut{
			Major:    linux.FUSE_KERNEL_VERSION,
			Minor:    linux.FUSE_KERNEL_MINOR_VERSION,
			MaxWrite: testMaxWrite,
		}
		respLen := uint32(linux.SizeOfFUSEHeaderOut) + uint32(initOut.SizeBytes())
		respBuf := make([]byte, respLen)

		respHdr := linux.FUSEHeaderOut{
			Len:    respLen,
			Error:  0,
			Unique: reqHdr.Unique,
		}
		respHdr.MarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])
		initOut.MarshalUnsafe(respBuf[linux.SizeOfFUSEHeaderOut:])

		if _, err := unix.Write(fds[1], respBuf); err != nil {
			t.Errorf("server Write: %v", err)
		}
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
	if !conn.connInitSuccess {
		t.Error("connInitSuccess not set")
	}
	if conn.maxWrite < fuseMinMaxWrite {
		t.Errorf("maxWrite = %d, want >= %d", conn.maxWrite, fuseMinMaxWrite)
	}
	conn.mu.Unlock()
}

func TestHostConnectionCallAsync(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, serverFD, cleanup := newTestHostConnection(t)
	defer cleanup()

	done := make(chan struct{})
	go echoServerN(t, serverFD, 2, done)

	creds := auth.CredentialsFromContext(s.Ctx)
	asyncPayload := primitive.Uint32(99)
	asyncReq := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &asyncPayload)

	if err := hc.CallAsync(s.Ctx, asyncReq); err != nil {
		t.Fatalf("CallAsync: %v", err)
	}

	// Make a subsequent sync Call to verify no stale data in the FD.
	syncPayload := primitive.Uint32(123)
	syncReq := hc.conn.NewRequest(creds, 2, 2, echoTestOpcode, &syncPayload)

	resp, err := hc.Call(s.Ctx, syncReq)
	if err != nil {
		t.Fatalf("Call after CallAsync: %v", err)
	}
	<-done

	if resp.hdr.Unique != syncReq.hdr.Unique {
		t.Fatalf("unique mismatch after async: got %d, want %d", resp.hdr.Unique, syncReq.hdr.Unique)
	}

	var got primitive.Uint32
	if err := resp.UnmarshalPayload(&got); err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if got != syncPayload {
		t.Fatalf("payload after async: got %d, want %d", got, syncPayload)
	}
	resp.Release()

	// The async reply is discarded (and its buffer released) by the reader; the
	// sync reply was released above. The pool must balance.
	if !hc.pool.balanced() {
		t.Errorf("buffer pool not balanced after async+sync round-trips")
	}
}

func TestHostConnectionConcurrent(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, serverFD, cleanup := newTestHostConnection(t)
	defer cleanup()

	const numRequests = 10

	serverDone := make(chan struct{})
	go echoServerN(t, serverFD, numRequests, serverDone)

	creds := auth.CredentialsFromContext(s.Ctx)

	var wg sync.WaitGroup
	errs := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(val uint32) {
			defer wg.Done()
			payload := primitive.Uint32(val)
			req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &payload)

			// Each goroutine needs its own context because NoTask.Block
			// has unsynchronized state.
			ctx := kernel.KernelFromContext(s.Ctx).SupervisorContext()
			resp, err := hc.Call(ctx, req)
			if err != nil {
				errs <- err
				return
			}
			if resp.hdr.Unique != req.hdr.Unique {
				errs <- linuxerr.EINVAL
				return
			}
			var got primitive.Uint32
			if err := resp.UnmarshalPayload(&got); err != nil {
				errs <- err
				return
			}
			if got != payload {
				errs <- linuxerr.EINVAL
				return
			}
			resp.Release()
		}(uint32(i))
	}

	wg.Wait()
	close(errs)
	<-serverDone

	if !hc.pool.balanced() {
		t.Errorf("buffer pool not balanced after %d concurrent round-trips", numRequests)
	}

	for err := range errs {
		t.Fatalf("concurrent call failed: %v", err)
	}
}

// drainServer reads count requests from serverFD and discards them without
// ever writing a reply. It signals completion on done. Used to model a server
// receiving no-reply requests (e.g. FUSE_FORGET).
func drainServer(t *testing.T, serverFD int, count int, done chan struct{}) {
	t.Helper()
	defer close(done)

	buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	for i := 0; i < count; i++ {
		if _, err := unix.Read(serverFD, buf); err != nil {
			t.Errorf("drainServer Read %d: %v", i, err)
			return
		}
	}
}

// forgetAwareServer reads count requests from serverFD. It echoes a reply for
// any request whose opcode is not FUSE_FORGET, and silently drains (never
// replies to) FUSE_FORGET requests. It signals completion on done.
func forgetAwareServer(t *testing.T, serverFD int, count int, done chan struct{}) {
	t.Helper()
	defer close(done)

	buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	for i := 0; i < count; i++ {
		n, err := unix.Read(serverFD, buf)
		if err != nil {
			t.Errorf("forgetAwareServer Read %d: %v", i, err)
			return
		}
		if n < int(linux.SizeOfFUSEHeaderIn) {
			t.Errorf("forgetAwareServer: short read %d bytes on request %d", n, i)
			return
		}

		var reqHdr linux.FUSEHeaderIn
		reqHdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])
		if reqHdr.Opcode == linux.FUSE_FORGET {
			// No reply for FUSE_FORGET.
			continue
		}

		payload := buf[linux.SizeOfFUSEHeaderIn:n]
		respLen := linux.SizeOfFUSEHeaderOut + uint32(len(payload))
		respBuf := make([]byte, respLen)
		respHdr := linux.FUSEHeaderOut{
			Len:    respLen,
			Error:  0,
			Unique: reqHdr.Unique,
		}
		respHdr.MarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])
		copy(respBuf[linux.SizeOfFUSEHeaderOut:], payload)
		if _, err := unix.Write(serverFD, respBuf); err != nil {
			t.Errorf("forgetAwareServer Write %d: %v", i, err)
			return
		}
	}
}

// activeRequestState reads the connection's completion-map size and active
// request count under conn.mu.
func activeRequestState(hc *hostConnection) (numCompletions int, numActive uint64) {
	hc.conn.mu.Lock()
	defer hc.conn.mu.Unlock()
	return len(hc.conn.completions), hc.conn.numActiveRequests
}

// TestHostConnectionNoReplyDoesNotLeak verifies that no-reply requests
// (e.g. FUSE_FORGET) sent over the host FD do not permanently occupy a
// completion-map entry or an active-request slot. Such requests never receive
// a reply, so if call() registered a completion for them it would leak.
func TestHostConnectionNoReplyDoesNotLeak(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, serverFD, cleanup := newTestHostConnection(t)
	defer cleanup()

	const numForgets = 5
	done := make(chan struct{})
	go drainServer(t, serverFD, numForgets, done)

	creds := auth.CredentialsFromContext(s.Ctx)
	for i := 0; i < numForgets; i++ {
		payload := primitive.Uint32(uint32(i))
		req := hc.conn.NewRequest(creds, 1, uint64(i), linux.FUSE_FORGET, &payload)
		req.noReply = true
		if err := hc.CallAsync(s.Ctx, req); err != nil {
			t.Fatalf("CallAsync forget %d: %v", i, err)
		}
	}

	<-done

	if nComp, nActive := activeRequestState(hc); nComp != 0 || nActive != 0 {
		t.Errorf("no-reply requests leaked state: completions=%d, numActiveRequests=%d; want 0, 0", nComp, nActive)
	}
}

// TestHostConnectionNoReplyInterleaved verifies that a normal reply-bearing
// request interleaved between no-reply requests still completes correctly, and
// that the connection's accounting settles back to zero afterwards.
func TestHostConnectionNoReplyInterleaved(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, serverFD, cleanup := newTestHostConnection(t)
	defer cleanup()

	// Three requests on the wire: forget, echo, forget.
	done := make(chan struct{})
	go forgetAwareServer(t, serverFD, 3, done)

	creds := auth.CredentialsFromContext(s.Ctx)

	forget1Payload := primitive.Uint32(1)
	forget1 := hc.conn.NewRequest(creds, 1, 1, linux.FUSE_FORGET, &forget1Payload)
	forget1.noReply = true
	if err := hc.CallAsync(s.Ctx, forget1); err != nil {
		t.Fatalf("CallAsync forget1: %v", err)
	}

	echoPayload := primitive.Uint32(42)
	echoReq := hc.conn.NewRequest(creds, 1, 2, echoTestOpcode, &echoPayload)
	resp, err := hc.Call(s.Ctx, echoReq)
	if err != nil {
		t.Fatalf("Call echo: %v", err)
	}
	var got primitive.Uint32
	if err := resp.UnmarshalPayload(&got); err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if got != echoPayload {
		t.Fatalf("echo payload: got %d, want %d", got, echoPayload)
	}

	forget2Payload := primitive.Uint32(2)
	forget2 := hc.conn.NewRequest(creds, 1, 3, linux.FUSE_FORGET, &forget2Payload)
	forget2.noReply = true
	if err := hc.CallAsync(s.Ctx, forget2); err != nil {
		t.Fatalf("CallAsync forget2: %v", err)
	}

	<-done

	if nComp, nActive := activeRequestState(hc); nComp != 0 || nActive != 0 {
		t.Errorf("interleaved no-reply leaked state: completions=%d, numActiveRequests=%d; want 0, 0", nComp, nActive)
	}
}

// TestHostConnectionRejectsCheckpoint verifies that a host-FD connection rejects
// checkpoint (beforeSave panics), while a device-FD connection does not.
func TestHostConnectionRejectsCheckpoint(t *testing.T) {
	hc, _, cleanup := newTestHostConnection(t)
	defer cleanup()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected beforeSave to panic for a host-FD connection")
			}
		}()
		hc.conn.beforeSave()
	}()

	fsopts := filesystemOptions{
		maxActiveRequests: maxActiveRequestsDefault,
		maxRead:           4096,
	}
	dconn, err := newFUSEConnectionOpts(&fsopts)
	if err != nil {
		t.Fatalf("newFUSEConnectionOpts: %v", err)
	}
	// A device-FD connection must not panic.
	dconn.beforeSave()
}

func TestHostConnectionNotConnected(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, _, cleanup := newTestHostConnection(t)
	defer cleanup()

	// Disconnect the connection.
	hc.conn.mu.Lock()
	hc.conn.connected = false
	hc.conn.mu.Unlock()

	creds := auth.CredentialsFromContext(s.Ctx)
	testObj := primitive.Uint32(0)
	req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &testObj)

	_, err := hc.Call(s.Ctx, req)
	if !linuxerr.Equals(linuxerr.ENOTCONN, err) {
		t.Fatalf("expected ENOTCONN, got %v", err)
	}
}
