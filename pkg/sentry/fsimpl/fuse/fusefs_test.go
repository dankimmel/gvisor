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
	"math"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// baseMountOpts contains the mandatory options every fusefs mount requires.
const baseMountOpts = "fd=1,user_id=0,group_id=0,rootmode=40000"

func TestParseOptionsHostFDMemoryOptions(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	creds := auth.CredentialsFromContext(s.Ctx)

	for _, tc := range []struct {
		name                    string
		data                    string
		wantInflight            uint64
		wantReplyBufMax         uint32
		wantReplyBufConcurrency uint32
	}{
		{
			name:                    "defaults",
			data:                    baseMountOpts,
			wantInflight:            maxActiveRequestsDefault,
			wantReplyBufMax:         fuseDefaultReplyBufMax,
			wantReplyBufConcurrency: fuseDefaultReplyBufConcurrency,
		},
		{
			name:                    "explicit",
			data:                    baseMountOpts + ",max_inflight=500,reply_buf_max=262144,reply_buf_concurrency=8",
			wantInflight:            500,
			wantReplyBufMax:         262144,
			wantReplyBufConcurrency: 8,
		},
		{
			name:                    "clamp-above-ceiling",
			data:                    baseMountOpts + fmt.Sprintf(",max_inflight=%d,reply_buf_max=%d,reply_buf_concurrency=%d", uint64(1)<<40, uint64(1)<<40, uint64(1)<<40),
			wantInflight:            fuseMaxMaxInflight,
			wantReplyBufMax:         fuseMaxReplyBuf,
			wantReplyBufConcurrency: fuseMaxReplyBufConcurrency,
		},
		{
			name:                    "clamp-below-floor",
			data:                    baseMountOpts + ",max_inflight=0,reply_buf_max=1,reply_buf_concurrency=0",
			wantInflight:            1,
			wantReplyBufMax:         fuseMinReplyBuf,
			wantReplyBufConcurrency: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsopts, _, err := parseOptions(s.Ctx, creds, tc.data)
			if err != nil {
				t.Fatalf("parseOptions(%q): %v", tc.data, err)
			}
			if fsopts.maxInflight != tc.wantInflight {
				t.Errorf("maxInflight = %d, want %d", fsopts.maxInflight, tc.wantInflight)
			}
			if fsopts.replyBufMax != tc.wantReplyBufMax {
				t.Errorf("replyBufMax = %d, want %d", fsopts.replyBufMax, tc.wantReplyBufMax)
			}
			if fsopts.replyBufConcurrency != tc.wantReplyBufConcurrency {
				t.Errorf("replyBufConcurrency = %d, want %d", fsopts.replyBufConcurrency, tc.wantReplyBufConcurrency)
			}
		})
	}
}

func TestParseOptionsInvalidMemoryOptions(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	creds := auth.CredentialsFromContext(s.Ctx)

	for _, opt := range []string{
		"max_inflight=notanumber",
		"reply_buf_max=xyz",
		"reply_buf_concurrency=@",
	} {
		if _, _, err := parseOptions(s.Ctx, creds, baseMountOpts+","+opt); err == nil {
			t.Errorf("parseOptions with %q: got nil error, want EINVAL", opt)
		}
	}
}

func TestClampHostFDOptions(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hdr := uint32(linux.SizeOfFUSEHeaderOut)
	for _, tc := range []struct {
		name        string
		maxRead     uint32
		replyBufMax uint32
		wantMaxRead uint32
	}{
		{
			name:        "upper-clamp",
			maxRead:     math.MaxUint32,
			replyBufMax: fuseMaxReplyBuf,
			wantMaxRead: fuseMaxMaxRead,
		},
		{
			name:        "coupling-clamps-max-read-down",
			maxRead:     100000,
			replyBufMax: 65536,
			wantMaxRead: 65536 - hdr,
		},
		{
			name:        "no-clamp-needed",
			maxRead:     4096,
			replyBufMax: fuseDefaultReplyBufMax,
			wantMaxRead: 4096,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsopts := &filesystemOptions{maxRead: tc.maxRead, replyBufMax: tc.replyBufMax}
			clampHostFDOptions(s.Ctx, fsopts)
			if fsopts.maxRead != tc.wantMaxRead {
				t.Errorf("maxRead = %d, want %d", fsopts.maxRead, tc.wantMaxRead)
			}
		})
	}
}
