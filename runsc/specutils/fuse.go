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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
)

// FUSEMountType is the OCI mount type identifying a runsc-provisioned host-FD
// FUSE mount. It matches the Sentry's fuse.Name.
const FUSEMountType = "fuse"

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

// ValidateFUSESocketSource checks that a runsc-provisioned host-FD FUSE mount's
// backend Unix-domain-socket path is permitted: it must be a clean absolute
// path strictly inside one of the comma-separated directories in allowedDirs.
// An empty allowedDirs disables the feature. This is the runsc-side gate on an
// otherwise untrusted (e.g. pod-annotation-supplied) socket path; the Sentry
// never dials the host, so this is the only place the path is vetted.
func ValidateFUSESocketSource(source, allowedDirs string) error {
	if strings.TrimSpace(allowedDirs) == "" {
		return fmt.Errorf("host-FD FUSE mounts are disabled: --fuse-allowed-socket-dirs is empty")
	}
	if !filepath.IsAbs(source) {
		return fmt.Errorf("fuse backend socket path %q must be absolute", source)
	}
	clean := filepath.Clean(source)
	for _, dir := range strings.Split(allowedDirs, ",") {
		dir = strings.TrimSpace(dir)
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(dir), clean)
		if err != nil {
			continue
		}
		// Accept only paths strictly inside dir (not dir itself, and not
		// escaping it via "..").
		if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return nil
	}
	return fmt.Errorf("fuse backend socket path %q is not inside any --fuse-allowed-socket-dirs entry", source)
}

// FUSEMountFD pairs a fuse mount destination with the connected backend socket.
// The caller owns and must close File (typically by donating it to the sandbox).
type FUSEMountFD struct {
	Destination string
	File        *os.File
}

// DialFUSEMounts finds fuse-type mounts in spec, validates each backend socket
// path against allowedDirs, dials it (with the given per-connection timeout),
// and returns the connected files in spec-mount order. On any error every
// already-dialed file is closed. An empty allowedDirs with no fuse mounts is not
// an error; a fuse mount present with the feature disabled is.
func DialFUSEMounts(spec *specs.Spec, allowedDirs string, timeout time.Duration) ([]FUSEMountFD, error) {
	var out []FUSEMountFD
	closeAll := func() {
		for _, m := range out {
			m.File.Close()
		}
	}
	for i := range spec.Mounts {
		m := &spec.Mounts[i]
		if m.Type != FUSEMountType {
			continue
		}
		if err := ValidateFUSESocketSource(m.Source, allowedDirs); err != nil {
			closeAll()
			return nil, err
		}
		conn, err := net.DialTimeout("unix", m.Source, timeout)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("dialing fuse backend %q for mount %q: %w", m.Source, m.Destination, err)
		}
		uconn, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			closeAll()
			return nil, fmt.Errorf("fuse backend %q is not a unix socket", m.Source)
		}
		// File() returns a dup of the socket FD as an *os.File; close the
		// net.Conn, keeping the dup.
		f, err := uconn.File()
		uconn.Close()
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("obtaining fd for fuse backend %q: %w", m.Source, err)
		}
		out = append(out, FUSEMountFD{Destination: m.Destination, File: f})
	}
	return out, nil
}

// FUSEMountData builds the fusefs mount-option string for a runsc-provisioned
// host-FD FUSE mount: the connection fd, the synthesized mandatory options
// (user_id/group_id/rootmode), and the memory-limit tuning options. The Sentry
// re-parses and clamps every value; these are conveniences, not enforcement.
func FUSEMountData(fd int, uid, gid uint32, rootMode uint32, limits FUSEMemoryLimits) string {
	return fmt.Sprintf("fd=%d,user_id=%d,group_id=%d,rootmode=%o,max_inflight=%d,reply_buf_max=%d,reply_buf_concurrency=%d",
		fd, uid, gid, rootMode, limits.MaxInflight, limits.ReplyBufMax, limits.ReplyBufConcurrency)
}
