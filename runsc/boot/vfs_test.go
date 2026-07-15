// Copyright 2021 The gVisor Authors.
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

package boot

import (
	"os"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/fuse"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestGetMountAccessType(t *testing.T) {
	const source = "foo"
	for _, tst := range []struct {
		name        string
		annotations map[string]string
		want        config.FileAccessType
	}{
		{
			name: "container=exclusive",
			annotations: map[string]string{
				MountPrefix + "mount1.source": source,
				MountPrefix + "mount1.type":   "bind",
				MountPrefix + "mount1.share":  "container",
			},
			want: config.FileAccessExclusive,
		},
		{
			name: "pod=shared",
			annotations: map[string]string{
				MountPrefix + "mount1.source": source,
				MountPrefix + "mount1.type":   "bind",
				MountPrefix + "mount1.share":  "pod",
			},
			want: config.FileAccessShared,
		},
		{
			name: "share=shared",
			annotations: map[string]string{
				MountPrefix + "mount1.source": source,
				MountPrefix + "mount1.type":   "bind",
				MountPrefix + "mount1.share":  "shared",
			},
			want: config.FileAccessShared,
		},
		{
			name: "default=shared",
			annotations: map[string]string{
				MountPrefix + "mount1.source": source + "mismatch",
				MountPrefix + "mount1.type":   "bind",
				MountPrefix + "mount1.share":  "container",
			},
			want: config.FileAccessShared,
		},
		{
			name: "tmpfs+container=exclusive",
			annotations: map[string]string{
				MountPrefix + "mount1.source": source,
				MountPrefix + "mount1.type":   "tmpfs",
				MountPrefix + "mount1.share":  "container",
			},
			want: config.FileAccessExclusive,
		},
		{
			name: "tmpfs+pod=exclusive",
			annotations: map[string]string{
				MountPrefix + "mount1.source": source,
				MountPrefix + "mount1.type":   "tmpfs",
				MountPrefix + "mount1.share":  "pod",
			},
			want: config.FileAccessExclusive,
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			spec := &specs.Spec{Annotations: tst.annotations}
			podHints, err := NewPodMountHints(spec)
			if err != nil {
				t.Fatalf("newPodMountHints failed: %v", err)
			}
			conf := &config.Config{FileAccessMounts: config.FileAccessShared}
			if got := getMountAccessType(conf, podHints.FindMount(source)); got != tst.want {
				t.Errorf("getMountAccessType(), got: %v, want: %v", got, tst.want)
			}
		})
	}
}

func TestGoferMountDataDirectFS(t *testing.T) {
	for _, tc := range []struct {
		name             string
		directFS         bool
		suppressDirectFS bool
		wantEnabled      bool
	}{
		{
			name:        "global on, not suppressed",
			directFS:    true,
			wantEnabled: true,
		},
		{
			name:             "global on, suppressed",
			directFS:         true,
			suppressDirectFS: true,
			wantEnabled:      false,
		},
		{
			name:             "global off, suppressed",
			directFS:         false,
			suppressDirectFS: true,
			wantEnabled:      false,
		},
		{
			name:        "global off, not suppressed",
			directFS:    false,
			wantEnabled: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &config.Config{DirectFS: tc.directFS, HostFifo: config.HostFifoOpen}
			opts := goferMountData(7, config.FileAccessExclusive, conf, tc.suppressDirectFS)
			gotEnabled := slices.Contains(opts, "directfs")
			if gotEnabled != tc.wantEnabled {
				t.Errorf("directfs option present = %t, want %t (opts=%v)", gotEnabled, tc.wantEnabled, opts)
			}
		})
	}
}

func TestGetMountNameAndOptionsFUSE(t *testing.T) {
	// A pipe FD stands in for the donated backend socket FD.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	conf := &config.Config{
		FUSEMaxInflight:         9999,
		FUSEReplyBufMax:         262144,
		FUSEReplyBufConcurrency: 8,
	}
	// A container annotation overrides the flag default for max_inflight.
	spec := &specs.Spec{
		Annotations: map[string]string{
			specutils.AnnotationFUSEMaxInflight: "500",
		},
	}
	m := &mountInfo{
		mount:   &specs.Mount{Type: fuse.Name, Destination: "/mnt/fuse"},
		goferFD: fd.New(int(r.Fd())),
	}

	fsName, opts, err := getMountNameAndOptions(spec, conf, m, "", "cont", "cid", nil)
	if err != nil {
		t.Fatalf("getMountNameAndOptions: %v", err)
	}
	if fsName != fuse.Name {
		t.Errorf("fsName = %q, want %q", fsName, fuse.Name)
	}
	if !opts.GetFilesystemOptions.InternalMount {
		t.Error("InternalMount not set for a fuse mount")
	}
	iopts, ok := opts.GetFilesystemOptions.InternalData.(fuse.InternalFilesystemOptions)
	if !ok {
		t.Fatalf("InternalData = %T, want fuse.InternalFilesystemOptions", opts.GetFilesystemOptions.InternalData)
	}
	if iopts.UniqueID.Path != "/mnt/fuse" || iopts.UniqueID.ContainerName != "cont" {
		t.Errorf("UniqueID = %+v, want {ContainerName: cont, Path: /mnt/fuse}", iopts.UniqueID)
	}
	data := opts.GetFilesystemOptions.Data
	for _, want := range []string{
		"host_fd=",
		"user_id=0",
		"group_id=0",
		"rootmode=",
		"max_inflight=500", // annotation override, not the flag default
		"reply_buf_max=262144",
		"reply_buf_concurrency=8",
	} {
		if !strings.Contains(data, want) {
			t.Errorf("mount data %q missing %q", data, want)
		}
	}
}

func TestGetMountNameAndOptionsFUSENoFD(t *testing.T) {
	conf := &config.Config{}
	spec := &specs.Spec{}
	m := &mountInfo{mount: &specs.Mount{Type: fuse.Name, Destination: "/mnt/fuse"}}
	if _, _, err := getMountNameAndOptions(spec, conf, m, "", "cont", "cid", nil); err == nil {
		t.Error("getMountNameAndOptions for a fuse mount without an FD: got nil error, want failure")
	}
}

func TestCgroupfsCPUDefaults(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rawQuota   int64
		rawPeriod  int64
		wantQuota  int64
		wantPeriod int64
	}{
		{
			name:       "finite quota",
			rawQuota:   150000,
			rawPeriod:  100000,
			wantQuota:  150000,
			wantPeriod: 100000,
		},
		{
			name:       "unlimited quota keeps linux default",
			rawQuota:   -1,
			rawPeriod:  100000,
			wantQuota:  -1,
			wantPeriod: 100000,
		},
		{
			name:       "unset period falls back to linux default period",
			rawQuota:   -1,
			rawPeriod:  0,
			wantQuota:  -1,
			wantPeriod: 100000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defaults := cgroupfsCPUDefaults(tc.rawQuota, tc.rawPeriod)
			if got := defaults["cpu.cfs_quota_us"]; got != tc.wantQuota {
				t.Errorf("quota = %d, want %d", got, tc.wantQuota)
			}
			if got := defaults["cpu.cfs_period_us"]; got != tc.wantPeriod {
				t.Errorf("period = %d, want %d", got, tc.wantPeriod)
			}
		})
	}
}
