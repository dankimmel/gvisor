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

package fusehost

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// fuseMountDest is where runsc mounts the provisioned FUSE filesystem inside the
// container.
const fuseMountDest = "/fuse"

// startBackingServer creates a backing directory seeded with the standard test
// files and a listening Unix socket that a runsc-provisioned FUSE mount can
// dial. It returns the backing dir and the socket path. The server accepts
// connections until the listener is closed, so it survives the transport being
// re-dialed across a checkpoint/restore.
func startBackingServer(t *testing.T) (backDir, sockPath string) {
	t.Helper()

	backDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(backDir, "testfile"), []byte("hello from the host FUSE server\n"), 0644); err != nil {
		t.Fatalf("seeding testfile: %v", err)
	}
	// Pre-create the heartbeat file: the minimal test server does not implement
	// create, so the workload opens it write-only without O_CREAT.
	if err := os.WriteFile(filepath.Join(backDir, "heartbeat"), nil, 0644); err != nil {
		t.Fatalf("seeding heartbeat: %v", err)
	}

	// Keep the socket in its own directory so the containing directory can be
	// used verbatim as an --fuse-allowed-socket-dirs entry.
	sockDir := t.TempDir()
	sockPath = filepath.Join(sockDir, "fuse.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix(%q): %v", sockPath, err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeUDS(ln, backDir)
	return backDir, sockPath
}

// runscProvisionedCmd builds a "runsc run" command for a container whose spec
// contains a runsc-provisioned fuse mount at fuseMountDest sourced from
// sockPath, with the given --fuse-allowed-socket-dirs value. The workload
// verifies the mount and exits.
func runscProvisionedCmd(t *testing.T, sockPath, allowedDirs string) *exec.Cmd {
	t.Helper()

	runscPath, err := testutil.FindFile("runsc/runsc")
	if err != nil {
		t.Fatalf("FindFile(runsc): %v", err)
	}
	workloadPath, err := testutil.FindFile("test/fuse_host/workload/workload")
	if err != nil {
		t.Fatalf("FindFile(workload): %v", err)
	}

	spec := testutil.NewSpecWithArgs(workloadPath, "--verify-dir="+fuseMountDest)
	// A runsc-provisioned host-FD FUSE mount: type "fuse", source is the backend
	// socket path. runsc dials the socket, validates it against the allowlist,
	// and donates the connected FD to the sandbox.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Type:        "fuse",
		Source:      sockPath,
		Destination: fuseMountDest,
	})

	bundleDir, cleanupBundle, err := testutil.SetupBundleDir(spec)
	if err != nil {
		t.Fatalf("SetupBundleDir: %v", err)
	}
	t.Cleanup(cleanupBundle)

	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("SetupRootDir: %v", err)
	}
	t.Cleanup(cleanupRoot)

	id := testutil.RandomContainerID()
	cmd := exec.Command(runscPath,
		"--root="+rootDir,
		"--rootless",
		"--TESTONLY-unsafe-nonroot",
		"--network=none",
		"--fuse-allowed-socket-dirs="+allowedDirs,
		"run",
		"--bundle="+bundleDir,
		id,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
	return cmd
}

// TestFuseHostProvisionedUDS exercises the runsc-provisioned path end to end:
// runsc dials a backend Unix socket named in the mount source, validates it
// against --fuse-allowed-socket-dirs, donates the connected FD to the sandbox,
// and mounts the FUSE filesystem at the mount destination with no in-container
// mount() call.
func TestFuseHostProvisionedUDS(t *testing.T) {
	_, sockPath := startBackingServer(t)
	allowedDirs := filepath.Dir(sockPath)

	cmd := runscProvisionedCmd(t, sockPath, allowedDirs)
	if err := cmd.Run(); err != nil {
		t.Fatalf("runsc run: %v", err)
	}
}

// TestFuseHostSocketNotInAllowlist verifies the runsc-side allowlist gate: a
// fuse mount whose backend socket is outside every --fuse-allowed-socket-dirs
// entry must fail fast at container creation, before the sandbox starts.
func TestFuseHostSocketNotInAllowlist(t *testing.T) {
	_, sockPath := startBackingServer(t)

	// Point the allowlist at an unrelated directory that does not contain the
	// socket.
	cmd := runscProvisionedCmd(t, sockPath, filepath.Join(t.TempDir(), "elsewhere"))
	if err := cmd.Run(); err == nil {
		t.Fatalf("runsc run with socket outside allowlist: got nil error, want failure")
	}
}

// TestFuseHostProvisionedFeatureDisabled verifies that a fuse mount with the
// feature disabled (empty --fuse-allowed-socket-dirs) is rejected rather than
// silently ignored.
func TestFuseHostProvisionedFeatureDisabled(t *testing.T) {
	_, sockPath := startBackingServer(t)

	cmd := runscProvisionedCmd(t, sockPath, "" /* allowedDirs */)
	if err := cmd.Run(); err == nil {
		t.Fatalf("runsc run with feature disabled: got nil error, want failure")
	}
}
