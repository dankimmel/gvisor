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

package specutils

import (
	"strings"
	"testing"
)

func TestFUSEMemoryLimitsFromAnnotations(t *testing.T) {
	def := FUSEMemoryLimits{MaxInflight: 10000, ReplyBufMax: 1 << 20, ReplyBufConcurrency: 16}

	for _, tc := range []struct {
		name        string
		annotations map[string]string
		container   string
		want        FUSEMemoryLimits
	}{
		{
			name:      "defaults-when-absent",
			container: "cont",
			want:      def,
		},
		{
			name: "override-all",
			annotations: map[string]string{
				AnnotationFUSEMaxInflight:         "500",
				AnnotationFUSEReplyBufMax:         "262144",
				AnnotationFUSEReplyBufConcurrency: "8",
			},
			container: "cont",
			want:      FUSEMemoryLimits{MaxInflight: 500, ReplyBufMax: 262144, ReplyBufConcurrency: 8},
		},
		{
			name: "container-specific-wins",
			annotations: map[string]string{
				AnnotationFUSEMaxInflight:           "500",
				AnnotationFUSEMaxInflight + ".cont": "999",
			},
			container: "cont",
			want:      FUSEMemoryLimits{MaxInflight: 999, ReplyBufMax: 1 << 20, ReplyBufConcurrency: 16},
		},
		{
			name: "container-specific-ignored-for-other-container",
			annotations: map[string]string{
				AnnotationFUSEMaxInflight + ".other": "999",
			},
			container: "cont",
			want:      def,
		},
		{
			name: "invalid-value-ignored",
			annotations: map[string]string{
				AnnotationFUSEMaxInflight: "notanumber",
			},
			container: "cont",
			want:      def,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FUSEMemoryLimitsFromAnnotations(tc.annotations, tc.container, def)
			if got != tc.want {
				t.Errorf("FUSEMemoryLimitsFromAnnotations() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestValidateFUSESocketSource(t *testing.T) {
	for _, tc := range []struct {
		name        string
		source      string
		allowedDirs string
		wantErr     bool
	}{
		{"disabled-empty-allowlist", "/run/fuse/backend.sock", "", true},
		{"allowed", "/run/fuse/backend.sock", "/run/fuse", false},
		{"allowed-among-multiple", "/var/run/x/b.sock", "/run/fuse,/var/run/x", false},
		{"allowed-nested", "/run/fuse/sub/dir/b.sock", "/run/fuse", false},
		{"not-in-allowlist", "/tmp/b.sock", "/run/fuse", true},
		{"relative-source", "run/fuse/b.sock", "/run/fuse", true},
		{"escape-via-dotdot", "/run/fuse/../etc/b.sock", "/run/fuse", true},
		{"is-the-dir-itself", "/run/fuse", "/run/fuse", true},
		{"prefix-not-boundary", "/run/fuse-evil/b.sock", "/run/fuse", true},
		{"relative-allowlist-entry-ignored", "/run/fuse/b.sock", "run/fuse", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFUSESocketSource(tc.source, tc.allowedDirs)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateFUSESocketSource(%q, %q) error = %v, wantErr = %v", tc.source, tc.allowedDirs, err, tc.wantErr)
			}
		})
	}
}

func TestFUSEMountData(t *testing.T) {
	limits := FUSEMemoryLimits{MaxInflight: 500, ReplyBufMax: 262144, ReplyBufConcurrency: 8}
	got := FUSEMountData(7, 0, 0, 040000, limits)
	for _, want := range []string{
		"fd=7",
		"user_id=0",
		"group_id=0",
		"rootmode=40000", // octal
		"max_inflight=500",
		"reply_buf_max=262144",
		"reply_buf_concurrency=8",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FUSEMountData() = %q, missing %q", got, want)
		}
	}
}

func TestDialFUSEMounts(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "backend.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	spec := &specs.Spec{Mounts: []specs.Mount{
		{Type: "bind", Source: "/somewhere", Destination: "/data"},
		{Type: FUSEMountType, Source: sockPath, Destination: "/mnt/fuse"},
	}}

	// Success: one fuse mount is dialed.
	got, err := DialFUSEMounts(spec, dir, time.Second)
	if err != nil {
		t.Fatalf("DialFUSEMounts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d dialed mounts, want 1", len(got))
	}
	if got[0].Destination != "/mnt/fuse" {
		t.Errorf("destination = %q, want /mnt/fuse", got[0].Destination)
	}
	got[0].File.Close()

	// Feature disabled (empty allowlist) with a fuse mount present is an error.
	if _, err := DialFUSEMounts(spec, "", time.Second); err == nil {
		t.Error("DialFUSEMounts with empty allowlist and a fuse mount: got nil error")
	}

	// Source outside the allowlist is an error.
	if _, err := DialFUSEMounts(spec, "/some/other/dir", time.Second); err == nil {
		t.Error("DialFUSEMounts with source outside allowlist: got nil error")
	}

	// No listener at the socket path is an error.
	badSpec := &specs.Spec{Mounts: []specs.Mount{
		{Type: FUSEMountType, Source: filepath.Join(dir, "absent.sock"), Destination: "/mnt/fuse"},
	}}
	if _, err := DialFUSEMounts(badSpec, dir, 200*time.Millisecond); err == nil {
		t.Error("DialFUSEMounts with no listener: got nil error")
	}

	// No fuse mounts, feature disabled: not an error.
	noFuse := &specs.Spec{Mounts: []specs.Mount{{Type: "bind", Source: "/x", Destination: "/y"}}}
	if got, err := DialFUSEMounts(noFuse, "", time.Second); err != nil || len(got) != 0 {
		t.Errorf("DialFUSEMounts with no fuse mounts: got %v, %v; want nil, nil", got, err)
	}
}
