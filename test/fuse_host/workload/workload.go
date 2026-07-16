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

// Binary workload runs inside a gVisor sandbox to exercise the FUSE host
// passthrough path. It mounts a FUSE filesystem using a pre-passed host FD,
// then performs filesystem operations to verify correctness.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

var (
	fuseFD    = flag.Int("fd", -1, "file descriptor for the FUSE connection (self-mount mode)")
	verifyDir = flag.String("verify-dir", "", "path of a runsc-provisioned FUSE mount to verify (no self-mount)")
	loop      = flag.Bool("loop", false, "with --verify-dir, hold a handle open and write heartbeats until killed")
)

const expectedTestfile = "hello from the host FUSE server\n"

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if *verifyDir != "" {
		return verifyProvisioned(*verifyDir, *loop)
	}
	if *fuseFD < 0 {
		return fmt.Errorf("one of --fd or --verify-dir is required")
	}

	mountPoint, err := os.MkdirTemp("", "fuse-mount")
	if err != nil {
		return fmt.Errorf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	mountOpts := fmt.Sprintf("fd=%d,user_id=0,group_id=0,rootmode=40000", *fuseFD)
	if err := unix.Mount("fuse", mountPoint, "fuse", unix.MS_NODEV|unix.MS_NOSUID, mountOpts); err != nil {
		return fmt.Errorf("mount: %v", err)
	}
	defer unix.Unmount(mountPoint, unix.MNT_DETACH)

	// Stat root directory.
	var st unix.Stat_t
	if err := unix.Stat(mountPoint, &st); err != nil {
		return fmt.Errorf("stat root: %v", err)
	}
	if st.Mode&unix.S_IFDIR == 0 {
		return fmt.Errorf("root is not a directory: mode=%o", st.Mode)
	}

	// Read testfile.
	testfilePath := filepath.Join(mountPoint, "testfile")
	data, err := os.ReadFile(testfilePath)
	if err != nil {
		return fmt.Errorf("read testfile: %v", err)
	}
	if string(data) != expectedTestfile {
		return fmt.Errorf("testfile content: got %q, want %q", string(data), expectedTestfile)
	}

	// Write new data to the existing file and read it back.
	writeData := "overwritten by sandbox workload\n"
	f, err := os.OpenFile(testfilePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open testfile for write: %v", err)
	}
	if _, err := f.Write([]byte(writeData)); err != nil {
		f.Close()
		return fmt.Errorf("write testfile: %v", err)
	}
	f.Close()

	data, err = os.ReadFile(testfilePath)
	if err != nil {
		return fmt.Errorf("re-read testfile: %v", err)
	}
	if string(data) != writeData {
		return fmt.Errorf("re-read content: got %q, want %q", string(data), writeData)
	}

	return nil
}

// verifyProvisioned exercises a mount that runsc itself provisioned and mounted
// (at dir) from a fuse-type OCI mount whose source is a backend Unix socket. The
// workload does not mount anything; it just reads and writes through the
// already-established mount.
//
// With loop set, it opens a "heartbeat" file once and writes to that held-open
// handle forever. This is the signal a checkpoint/restore test watches: after a
// checkpoint tears down the transport and a restore re-dials the backend, the
// Sentry must re-open this handle against the fresh session (Stage 7 replay)
// for the writes below to keep landing in the backing file.
func verifyProvisioned(dir string, loop bool) error {
	// The mount root must be a directory.
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		return fmt.Errorf("stat mount %q: %v", dir, err)
	}
	if st.Mode&unix.S_IFDIR == 0 {
		return fmt.Errorf("mount root is not a directory: mode=%o", st.Mode)
	}

	// Read the seed file the test placed in the backing directory.
	data, err := os.ReadFile(filepath.Join(dir, "testfile"))
	if err != nil {
		return fmt.Errorf("read testfile: %v", err)
	}
	if string(data) != expectedTestfile {
		return fmt.Errorf("testfile content: got %q, want %q", string(data), expectedTestfile)
	}

	if !loop {
		return nil
	}

	// The "heartbeat" file is pre-created empty by the test (the minimal test
	// server does not implement create/truncate). Open it write-only and append
	// through the held-open handle. Direct-IO writes land in the backing file
	// immediately, so the test can observe progress by the backing file's size.
	f, err := os.OpenFile(filepath.Join(dir, "heartbeat"), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open heartbeat: %v", err)
	}
	defer f.Close()
	for {
		if _, err := f.Write([]byte("x")); err != nil {
			return fmt.Errorf("heartbeat write: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
