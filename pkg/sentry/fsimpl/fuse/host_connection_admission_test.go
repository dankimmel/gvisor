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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// interruptibleContext wraps a base context but routes blocking through its own
// buffered cancel channel, so a test can Interrupt() a blocked Call
// deterministically (Interrupt before or during Block both work).
type interruptibleContext struct {
	context.Context
	cancel chan struct{}
}

func newInterruptibleContext(base context.Context) *interruptibleContext {
	return &interruptibleContext{Context: base, cancel: make(chan struct{}, 1)}
}

func (c *interruptibleContext) Block(ch <-chan struct{}) error {
	select {
	case <-c.cancel:
		return linuxerr.EINTR
	case <-ch:
		return nil
	}
}

func (c *interruptibleContext) Interrupt()        { c.cancel <- struct{}{} }
func (c *interruptibleContext) Interrupted() bool { return len(c.cancel) > 0 }
func (c *interruptibleContext) Killed() bool      { return false }

// newAdmissionTestConnection builds a SOCK_STREAM host connection with the given
// active-request bound. The returned cleanup is idempotent.
func newAdmissionTestConnection(t *testing.T, maxActive uint64) (*hostConnection, int, func()) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	fsopts := filesystemOptions{maxActiveRequests: maxActive, maxRead: 4096}
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
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			unix.Shutdown(fds[1], unix.SHUT_RDWR)
			unix.Shutdown(fds[0], unix.SHUT_RDWR)
			unix.Close(fds[0])
			unix.Close(fds[1])
		})
	}
	return hc, fds[1], cleanup
}

func numActive(hc *hostConnection) uint64 {
	hc.conn.mu.Lock()
	defer hc.conn.mu.Unlock()
	return hc.conn.numActiveRequests
}

// waitForActive blocks until numActiveRequests reaches want, or fails.
func waitForActive(t *testing.T, hc *hostConnection, want uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if numActive(hc) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("numActiveRequests = %d, never reached %d", numActive(hc), want)
}

// startInflight issues an echo request on ctx that occupies a slot and blocks
// awaiting a reply, delivering the eventual result on the returned channel.
func startInflight(hc *hostConnection, ctx context.Context, creds *auth.Credentials, node uint64) chan callResult {
	zero := primitive.Uint32(0)
	req := hc.conn.NewRequest(creds, 1, node, echoTestOpcode, &zero)
	done := make(chan callResult, 1)
	go func() {
		resp, err := hc.Call(ctx, req)
		done <- callResult{resp, err}
	}()
	return done
}

func TestHostAdmissionNoReplyBypassesFullGate(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, _, cleanup := newAdmissionTestConnection(t, 1)
	defer cleanup()
	creds := auth.CredentialsFromContext(s.Ctx)

	// Occupy the single slot with an in-flight request.
	inflightDone := startInflight(hc, kernelSupervisorContext(s), creds, 1)
	waitForActive(t, hc, 1)

	// A noReply request must proceed even though the gate is full.
	zero := primitive.Uint32(0)
	forget := hc.conn.NewRequest(creds, 1, 2, linux.FUSE_FORGET, &zero)
	forget.noReply = true
	forgetDone := make(chan error, 1)
	go func() { forgetDone <- hc.CallAsync(kernelSupervisorContext(s), forget) }()
	select {
	case err := <-forgetDone:
		if err != nil {
			t.Fatalf("noReply CallAsync: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("noReply request blocked on the full admission gate")
	}

	// Tearing down aborts the in-flight caller; drain it before returning.
	cleanup()
	if res := <-inflightDone; res.resp != nil {
		res.resp.Release()
	}
}

func TestHostAdmissionBlocksAndUnblocks(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newAdmissionTestConnection(t, 1)
	defer cleanup()
	creds := auth.CredentialsFromContext(s.Ctx)

	// Read the in-flight request off the wire so we can reply to it later.
	inflightReqCh := make(chan linux.FUSEHeaderIn, 1)
	go func() {
		hdr, _ := serverReadRequest(t, serverFD)
		inflightReqCh <- hdr
	}()

	inflightDone := startInflight(hc, kernelSupervisorContext(s), creds, 1)
	waitForActive(t, hc, 1)
	inflightHdr := <-inflightReqCh

	// A second Call must block on admission (slot is full).
	secondDone := startInflight(hc, kernelSupervisorContext(s), creds, 2)
	select {
	case <-secondDone:
		t.Fatal("second Call should have blocked on the full gate")
	case <-time.After(200 * time.Millisecond):
	}

	// Completing the in-flight request frees the slot and unblocks the waiter.
	writeChunks(t, serverFD, buildReply(inflightHdr.Unique, 0, nil))
	select {
	case res := <-inflightDone:
		if res.resp != nil {
			res.resp.Release()
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight caller did not complete")
	}

	// The second caller now proceeds; reply to it too.
	go func() {
		hdr, _ := serverReadRequest(t, serverFD)
		writeChunks(t, serverFD, buildReply(hdr.Unique, 0, nil))
	}()
	select {
	case res := <-secondDone:
		if res.err != nil {
			t.Fatalf("second Call: %v", res.err)
		}
		if res.resp != nil {
			res.resp.Release()
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second Call did not unblock after slot freed")
	}
}

func TestHostAdmissionTeardownReleasesWaiter(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, _, cleanup := newAdmissionTestConnection(t, 1)
	defer cleanup()
	creds := auth.CredentialsFromContext(s.Ctx)

	inflightDone := startInflight(hc, kernelSupervisorContext(s), creds, 1)
	waitForActive(t, hc, 1)

	// A second Call blocks on admission.
	secondDone := startInflight(hc, kernelSupervisorContext(s), creds, 2)
	time.Sleep(100 * time.Millisecond) // let it reach the wait loop

	// Tearing the connection down must release both callers with ECONNABORTED.
	cleanup()

	for _, tc := range []struct {
		name string
		ch   chan callResult
	}{{"inflight", inflightDone}, {"waiter", secondDone}} {
		select {
		case res := <-tc.ch:
			if res.resp != nil {
				if !linuxerr.Equals(linuxerr.ECONNABORTED, res.resp.Error()) && res.err == nil {
					t.Errorf("%s: expected ECONNABORTED, got resp err %v", tc.name, res.resp.Error())
				}
				res.resp.Release()
			} else if res.err == nil {
				t.Errorf("%s: expected an error, got nil", tc.name)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s caller did not return after teardown", tc.name)
		}
	}
}

func TestHostAdmissionInterruptBlockedWaiter(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newAdmissionTestConnection(t, 1)
	defer cleanup()
	creds := auth.CredentialsFromContext(s.Ctx)

	inflightReqCh := make(chan linux.FUSEHeaderIn, 1)
	go func() {
		hdr, _ := serverReadRequest(t, serverFD)
		inflightReqCh <- hdr
	}()
	inflightDone := startInflight(hc, kernelSupervisorContext(s), creds, 1)
	waitForActive(t, hc, 1)
	inflightHdr := <-inflightReqCh

	// A second caller blocks on admission with an interruptible context.
	ictx := newInterruptibleContext(kernelSupervisorContext(s))
	secondDone := make(chan callResult, 1)
	go func() {
		zero := primitive.Uint32(0)
		req := hc.conn.NewRequest(creds, 1, 2, echoTestOpcode, &zero)
		resp, err := hc.Call(ictx, req)
		secondDone <- callResult{resp, err}
	}()
	time.Sleep(100 * time.Millisecond)

	// Interrupting the blocked waiter must return an error and leave the slot
	// accounting untouched (only the in-flight request holds a slot).
	ictx.Interrupt()
	select {
	case res := <-secondDone:
		if res.err == nil {
			t.Errorf("interrupted waiter: expected error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("interrupted waiter did not return")
	}
	if got := numActive(hc); got != 1 {
		t.Errorf("numActiveRequests = %d after interrupt, want 1", got)
	}

	// Complete the in-flight request and tidy up.
	writeChunks(t, serverFD, buildReply(inflightHdr.Unique, 0, nil))
	if res := <-inflightDone; res.resp != nil {
		res.resp.Release()
	}
}

func TestHostAdmissionInterruptInflightLateReply(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newAdmissionTestConnection(t, 4)
	defer cleanup()
	creds := auth.CredentialsFromContext(s.Ctx)

	// Read the request so we can send a late reply after interruption.
	reqCh := make(chan linux.FUSEHeaderIn, 1)
	go func() {
		hdr, _ := serverReadRequest(t, serverFD)
		reqCh <- hdr
	}()

	ictx := newInterruptibleContext(kernelSupervisorContext(s))
	done := make(chan callResult, 1)
	go func() {
		zero := primitive.Uint32(0)
		req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &zero)
		resp, err := hc.Call(ictx, req)
		done <- callResult{resp, err}
	}()
	waitForActive(t, hc, 1)
	reqHdr := <-reqCh

	// Interrupt the in-flight caller. Its error path removes the completion and
	// decrements the count.
	ictx.Interrupt()
	select {
	case res := <-done:
		if res.err == nil {
			t.Errorf("interrupted in-flight caller: expected error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("interrupted in-flight caller did not return")
	}
	if got := numActive(hc); got != 0 {
		t.Errorf("numActiveRequests = %d after interrupt, want 0", got)
	}

	// The late reply now arrives; the reader must reclaim its buffer via the
	// unknown-Unique path without a second decrement.
	writeChunks(t, serverFD, buildReply(reqHdr.Unique, 0, []byte("late")))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hc.pool.balanced() && numActive(hc) == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !hc.pool.balanced() {
		t.Errorf("pool not balanced after late reply was dropped")
	}
	if got := numActive(hc); got != 0 {
		t.Errorf("numActiveRequests = %d after late reply, want 0 (no double decrement)", got)
	}
}
