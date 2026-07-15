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
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

func TestDrainForSaveTimesOutThenSucceeds(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	hc, serverFD, cleanup := newAdmissionTestConnection(t, 4)
	defer cleanup()
	creds := auth.CredentialsFromContext(s.Ctx)

	// Read the request so we can reply to it later.
	reqCh := make(chan linux.FUSEOpID, 1)
	go func() {
		hdr, _ := serverReadRequest(t, serverFD)
		reqCh <- hdr.Unique
	}()

	inflightDone := startInflight(hc, kernelSupervisorContext(s), creds, 1)
	waitForActive(t, hc, 1)
	unique := <-reqCh

	// With a request in flight, drainForSave must time out.
	if err := hc.conn.drainForSave(50 * time.Millisecond); err == nil {
		t.Error("drainForSave: expected timeout with a request in flight, got nil")
	}

	// After the reply completes the request, drainForSave must succeed.
	writeChunks(t, serverFD, buildReply(unique, 0, nil))
	if res := <-inflightDone; res.resp != nil {
		res.resp.Release()
	}
	if err := hc.conn.drainForSave(3 * time.Second); err != nil {
		t.Errorf("drainForSave after drain: %v", err)
	}
}
