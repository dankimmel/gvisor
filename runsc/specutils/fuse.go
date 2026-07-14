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
	"strconv"

	"gvisor.dev/gvisor/pkg/log"
)

// Annotations that override the default host-FD FUSE memory limits for a
// container. Each may be suffixed with ".<container-name>" to target a single
// container; the container-specific key takes precedence over the bare key.
// Values are untrusted and are re-clamped Sentry-side.
const (
	// AnnotationFUSEMaxInflight overrides --fuse-max-inflight.
	AnnotationFUSEMaxInflight = "dev.gvisor.fuse.max-inflight"
	// AnnotationFUSEReplyBufMax overrides --fuse-reply-buf-max.
	AnnotationFUSEReplyBufMax = "dev.gvisor.fuse.reply-buf-max"
	// AnnotationFUSEReplyBufConcurrency overrides --fuse-reply-buf-concurrency.
	AnnotationFUSEReplyBufConcurrency = "dev.gvisor.fuse.reply-buf-concurrency"
)

// FUSEMemoryLimits holds the host-FD FUSE memory limits for a container. These
// are untrusted defaults handed to the Sentry, which re-clamps them.
type FUSEMemoryLimits struct {
	MaxInflight         uint64
	ReplyBufMax         uint64
	ReplyBufConcurrency uint64
}

// fuseAnnotationValue returns the value of a dev.gvisor.fuse.* annotation,
// preferring a container-specific "<base>.<containerName>" key over the bare
// base key.
func fuseAnnotationValue(annotations map[string]string, base, containerName string) (string, bool) {
	if containerName != "" {
		if v, ok := annotations[base+"."+containerName]; ok {
			return v, true
		}
	}
	v, ok := annotations[base]
	return v, ok
}

// FUSEMemoryLimitsFromAnnotations returns def with any dev.gvisor.fuse.*
// annotation overrides applied. A malformed annotation value is ignored (the
// default is kept) and logged; the Sentry re-clamps every value regardless.
func FUSEMemoryLimitsFromAnnotations(annotations map[string]string, containerName string, def FUSEMemoryLimits) FUSEMemoryLimits {
	out := def
	override := func(base string, dst *uint64) {
		v, ok := fuseAnnotationValue(annotations, base, containerName)
		if !ok {
			return
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			log.Warningf("specutils: ignoring invalid %s annotation %q: %v", base, v, err)
			return
		}
		*dst = n
	}
	override(AnnotationFUSEMaxInflight, &out.MaxInflight)
	override(AnnotationFUSEReplyBufMax, &out.ReplyBufMax)
	override(AnnotationFUSEReplyBufConcurrency, &out.ReplyBufConcurrency)
	return out
}
