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

import "testing"

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
