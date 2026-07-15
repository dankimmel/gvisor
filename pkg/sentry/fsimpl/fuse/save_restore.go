// Copyright 2024 The gVisor Authors.
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
	goContext "context"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// fuseSaveDrainTimeout bounds how long a host-FD checkpoint waits for in-flight
// requests to drain before failing.
const fuseSaveDrainTimeout = 30 * time.Second

func (fRes *futureResponse) afterLoad(goContext.Context) {
	fRes.ch = make(chan struct{})
}

func (conn *connection) afterLoad(goContext.Context) {
	// For host-FD connections, the transport is reconstructed by the
	// filesystem's CompleteRestore (fresh FD, re-INIT, replay walk); leave
	// fuseConn nil until then. The device path is restored directly.
	if !conn.isHostConn {
		conn.fuseConn = &deviceConn{conn: conn}
	}
}

func (conn *connection) saveFullQueueCh() int {
	return cap(conn.fullQueueCh)
}

func (conn *connection) loadFullQueueCh(_ goContext.Context, capacity int) {
	conn.fullQueueCh = make(chan struct{}, capacity)
}

// fuseChildEntry is a (name, inode) pair collected during a tree walk.
type fuseChildEntry struct {
	name  string
	child *inode
}

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context) error {
	// The device path saves as before.
	if !fs.conn.isHostConn {
		return nil
	}
	if len(fs.uniqueID.Path) == 0 {
		return fmt.Errorf("fuse: host-FD mount without a checkpoint identity cannot be saved")
	}
	// Wait for in-flight requests to complete before the transport (which is not
	// saved) is torn down, so no reply is lost.
	return fs.conn.drainForSave(fuseSaveDrainTimeout)
}

// BeforeResume implements
// vfs.FilesystemImplSaveRestoreExtension.BeforeResume. The host transport stays
// live across a save-and-continue, so there is nothing to discard.
func (fs *filesystem) BeforeResume(ctx context.Context) {}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	// The device path is restored directly by afterLoad.
	if !fs.conn.isHostConn {
		return nil
	}

	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	if fdmap == nil {
		return fmt.Errorf("fuse: no restore FD map available")
	}
	hostFD, ok := fdmap[fs.uniqueID]
	if !ok {
		return fmt.Errorf("fuse: no backend FD for mount %q in restore FD map", fs.uniqueID.Path)
	}

	// Rebuild the host transport against the freshly re-dialed backend FD and
	// re-run the INIT handshake. The transport uses blocking I/O.
	if err := unix.SetNonblock(hostFD, false); err != nil {
		return fmt.Errorf("fuse restore: clearing O_NONBLOCK: %w", err)
	}
	savedMaxWrite := fs.conn.maxWrite
	hc := newHostConnection(fs.conn, int32(hostFD))
	fs.conn.mu.Lock()
	fs.conn.fuseConn = hc
	fs.conn.connected = true
	fs.conn.mu.Unlock()

	creds := auth.CredentialsFromContext(ctx)
	if err := hc.InitSend(creds, 0 /* pid */, true /* hasSysAdminCap */); err != nil {
		return fmt.Errorf("fuse restore: re-INIT: %w", err)
	}
	// A backend that re-negotiates a smaller maxWrite than the saved session
	// assumed would invalidate saved state; fail the restore.
	if fs.conn.maxWrite < savedMaxWrite {
		return fmt.Errorf("fuse restore: re-negotiated maxWrite %d < saved %d; incompatible backend", fs.conn.maxWrite, savedMaxWrite)
	}

	// Replay: re-learn every nodeID by path, then re-open every live handle.
	rootInode, ok := fs.root.Inode().(*inode)
	if !ok {
		return fmt.Errorf("fuse restore: root inode has unexpected type %T", fs.root.Inode())
	}
	if err := fs.restoreInodeTree(ctx, rootInode); err != nil {
		return err
	}
	return fs.reopenFDs(ctx)
}

// restoreInodeTree re-issues FUSE_LOOKUP for every descendant of parent to
// re-learn its nodeID in the new backend session, rewriting it in place.
// parent's nodeID must already be valid (the root is always FUSE_ROOT_ID).
func (fs *filesystem) restoreInodeTree(ctx context.Context, parent *inode) error {
	var children []fuseChildEntry
	parent.OrderedChildren.ForEachChild(func(name string, child kernfs.Inode) {
		if ci, ok := child.(*inode); ok {
			children = append(children, fuseChildEntry{name: name, child: ci})
		}
	})
	for _, c := range children {
		in := linux.FUSELookupIn{Name: linux.CString(c.name)}
		req := fs.conn.NewRequest(auth.CredentialsFromContext(ctx), 0, parent.nodeID, linux.FUSE_LOOKUP, &in)
		res, err := fs.conn.Call(ctx, req)
		if err != nil {
			return fmt.Errorf("fuse restore: re-LOOKUP %q: %w", c.name, err)
		}
		if err := res.Error(); err != nil {
			res.Release()
			return fmt.Errorf("fuse restore: re-LOOKUP %q failed: %w", c.name, err)
		}
		var out linux.FUSEEntryOut
		if err := res.UnmarshalPayload(&out); err != nil {
			res.Release()
			return fmt.Errorf("fuse restore: unmarshal re-LOOKUP %q: %w", c.name, err)
		}
		res.Release()

		c.child.nodeID = out.NodeID
		c.child.generation = out.Generation
		if err := fs.restoreInodeTree(ctx, c.child); err != nil {
			return err
		}
	}
	return nil
}

// reopenFDs re-opens every live file handle in the new session so that FDs held
// open across checkpoint continue to work.
func (fs *filesystem) reopenFDs(ctx context.Context) error {
	fs.openMu.Lock()
	fds := make([]*fileDescription, 0, len(fs.openFDs))
	for fd := range fs.openFDs {
		fds = append(fds, fd)
	}
	fs.openMu.Unlock()

	for _, fd := range fds {
		if err := fs.reopenFD(ctx, fd); err != nil {
			return err
		}
	}
	return nil
}

// reopenFD re-issues OPEN/OPENDIR for a single file description, rewriting its
// server file handle.
func (fs *filesystem) reopenFD(ctx context.Context, fd *fileDescription) error {
	i := fd.inode()
	isDir := i.filemode().IsDir()
	// If the server doesn't implement open for regular files, there is no handle
	// to restore.
	if fs.conn.noOpen && !isDir {
		return nil
	}
	opcode := linux.FUSEOpcode(linux.FUSE_OPEN)
	if isDir {
		opcode = linux.FUSE_OPENDIR
	}
	in := linux.FUSEOpenIn{Flags: fd.statusFlags() & ^uint32(linux.O_CREAT|linux.O_EXCL|linux.O_NOCTTY)}
	out := linux.FUSEOpenOut{}
	if err := i.call(ctx, opcode, &in, &out); err != nil {
		if linuxerr.Equals(linuxerr.ENOSYS, err) && !isDir {
			return nil // server doesn't support open; nothing to restore
		}
		return fmt.Errorf("fuse restore: re-open nodeID %d: %w", i.nodeID, err)
	}
	fd.Fh = out.Fh
	fd.OpenFlag = out.OpenFlag
	return nil
}
