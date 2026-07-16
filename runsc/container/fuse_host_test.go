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

package container

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/sandbox"
	fusehost "gvisor.dev/gvisor/test/fuse_host"
)

// startFUSEBackend seeds a backing directory and starts a FUSE server that
// listens on a Unix socket, ready to be dialed by a runsc-provisioned mount. It
// returns the backing dir and the socket's parent directory (suitable as an
// --fuse-allowed-socket-dirs entry) and the socket path itself. The listener is
// closed on test cleanup; it keeps accepting so the transport can be re-dialed
// across a checkpoint/restore.
func startFUSEBackend(t *testing.T) (backDir, sockDir, sockPath string) {
	t.Helper()

	backDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(backDir, "testfile"), []byte("hello from the host FUSE server\n"), 0644); err != nil {
		t.Fatalf("seeding testfile: %v", err)
	}
	// The minimal server does not implement create, so pre-create the heartbeat
	// file the workload appends to.
	if err := os.WriteFile(filepath.Join(backDir, "heartbeat"), nil, 0644); err != nil {
		t.Fatalf("seeding heartbeat: %v", err)
	}

	sockDir = t.TempDir()
	sockPath = filepath.Join(sockDir, "fuse.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix(%q): %v", sockPath, err)
	}
	t.Cleanup(func() { ln.Close() })
	go fusehost.ServeUDS(ln, backDir)
	return backDir, sockDir, sockPath
}

// waitForSizeAtLeast polls path until it is at least min bytes, returning the
// observed size, or fails the test on timeout.
func waitForSizeAtLeast(t *testing.T, path string, min int64, timeout time.Duration) int64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		fi, err := os.Stat(path)
		if err == nil && fi.Size() >= min {
			return fi.Size()
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %q to reach %d bytes (last err=%v)", path, min, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestFuseHostProvisionedCheckpointRestore checkpoints and restores a container
// with a runsc-provisioned host-FD FUSE mount, verifying the Sentry-driven
// replay restore (Stage 7): on restore, runsc re-dials the backend and the
// Sentry re-learns nodeids (FUSE_LOOKUP) and re-opens live handles (FUSE_OPEN)
// against the fresh session.
//
// The workload holds a "heartbeat" handle open and appends to it forever. The
// backing file is host-visible, so its growth is the observable signal:
//   - it grows while the container runs,
//   - it stops at checkpoint,
//   - it grows again after restore only if the held-open write handle was
//     successfully re-established against the new backend session.
func TestFuseHostProvisionedCheckpointRestore(t *testing.T) {
	backDir, sockDir, sockPath := startFUSEBackend(t)
	heartbeat := filepath.Join(backDir, "heartbeat")

	workloadPath, err := testutil.FindFile("test/fuse_host/workload/workload")
	if err != nil {
		t.Fatalf("FindFile(workload): %v", err)
	}

	conf := testutil.TestConfig(t)
	// Overlay would hide writes from the host-visible backing file; the FUSE
	// mount itself is never overlaid, but keep the config simple and direct.
	conf.Overlay2.Set("none")
	conf.FUSEAllowedSocketDirs = sockDir

	spec := testutil.NewSpecWithArgs(workloadPath, "--verify-dir=/fuse", "--loop")
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Type:        "fuse",
		Source:      sockPath,
		Destination: "/fuse",
	})

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("SetupContainer: %v", err)
	}
	defer cleanup()

	// Create and start the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("creating container: %v", err)
	}
	defer func() {
		if cont != nil {
			cont.Destroy()
		}
	}()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("starting container: %v", err)
	}

	// Wait until the workload has verified the mount and begun writing
	// heartbeats through the held-open handle.
	waitForSizeAtLeast(t, heartbeat, 1, 30*time.Second)

	// Checkpoint. With Resume=false (default) the container stops, so heartbeat
	// growth halts.
	imageDir, err := os.MkdirTemp(testutil.TmpDir(), "fuse-checkpoint")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(imageDir)
	if err := cont.Checkpoint(conf, imageDir, sandbox.CheckpointOpts{}); err != nil {
		t.Fatalf("checkpointing container: %v", err)
	}

	// Tear down the original container so nothing else writes the backing file,
	// then record the size at rest. Any growth beyond this is unambiguously from
	// the restored container.
	cont.Destroy()
	cont = nil
	fi, err := os.Stat(heartbeat)
	if err != nil {
		t.Fatalf("stat heartbeat after checkpoint: %v", err)
	}
	sizeAtRest := fi.Size()

	// Restore into a fresh container. New re-dials the backend and donates the
	// fresh FD; Restore replays the Sentry's state (re-LOOKUP of every path and
	// re-OPEN of the held-open handle) against the new session.
	args2 := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont2, err := New(conf, args2)
	if err != nil {
		t.Fatalf("creating restore container: %v", err)
	}
	defer cont2.Destroy()
	if err := cont2.Restore(conf, imageDir, false /* direct */, false /* background */, nil /* networkArgs */); err != nil {
		t.Fatalf("restoring container: %v", err)
	}
	if !cont2.Sandbox.Restored {
		t.Errorf("Sandbox.Restored = false, want true")
	}

	// The restored workload resumes appending through its re-established handle;
	// require growth past the checkpoint-time size.
	waitForSizeAtLeast(t, heartbeat, sizeAtRest+1, 30*time.Second)
}
