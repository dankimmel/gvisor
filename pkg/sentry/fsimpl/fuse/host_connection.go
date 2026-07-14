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
	"errors"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
)

// hostReadChunk is the size of a single read into the reader's accumulation
// buffer while assembling a frame header.
const hostReadChunk = 4096

// errBadFrame indicates a FUSE reply frame whose header Len is invalid (below
// the header size or above the negotiated maximum). FUSE stream framing has no
// resync point, so this is unrecoverable: the reader tears the connection down.
var errBadFrame = errors.New("fuse host connection: invalid frame length")

// errReaderClosed indicates the peer closed the FD (EOF) mid-stream.
var errReaderClosed = errors.New("fuse host connection: peer closed")

// hostConnection implements fuseConn for the host FD passthrough path.
// Instead of using the /dev/fuse device within the sandbox, it writes FUSE
// requests to and reads FUSE responses from a host FD. This allows a FUSE
// server running outside the sandbox to serve the filesystem.
//
// Multiple requests can be in flight concurrently. Writes are serialized by
// writeMu, while a background reader goroutine dispatches responses to callers
// via the connection's completions map.
type hostConnection struct {
	// conn holds shared FUSE connection state (protocol version, limits, etc).
	conn *connection

	// hostFD is the host file descriptor for the FUSE connection.
	hostFD int32

	// writeMu serializes write operations on hostFD.
	writeMu sync.Mutex

	// readBuf accumulates bytes read from hostFD that have not yet been consumed
	// as a complete frame (a partial header, or the read-ahead remainder of a
	// coalesced read). It is owned exclusively by the reader goroutine (and by
	// InitSend before the reader is started), so it needs no lock.
	readBuf []byte
}

// newHostConnection creates a hostConnection that communicates over hostFD.
func newHostConnection(conn *connection, hostFD int32) *hostConnection {
	return &hostConnection{
		conn:   conn,
		hostFD: hostFD,
	}
}

// startReader launches the background goroutine that reads responses from the
// host FD and dispatches them to waiting callers. Must be called after the
// FUSE_INIT handshake completes.
func (hc *hostConnection) startReader() {
	go hc.readLoop()
}

// maxFrame is the largest reply frame the reader will accept, in bytes. A
// well-behaved backend never exceeds this because a READ reply is bounded by
// the negotiated max_read (plus the fixed header).
func (hc *hostConnection) maxFrame() uint64 {
	return uint64(hc.conn.maxRead) + uint64(linux.SizeOfFUSEHeaderOut)
}

// readFD performs a single read, retrying on EINTR.
func readFD(fd int, p []byte) (int, error) {
	for {
		n, err := unix.Read(fd, p)
		if err == unix.EINTR {
			continue
		}
		return n, err
	}
}

// fillReadBuf reads up to hostReadChunk bytes from the host FD and appends them
// to the accumulation buffer.
func (hc *hostConnection) fillReadBuf() error {
	var scratch [hostReadChunk]byte
	n, err := readFD(int(hc.hostFD), scratch[:])
	if err != nil {
		return err
	}
	if n == 0 {
		return errReaderClosed
	}
	hc.readBuf = append(hc.readBuf, scratch[:n]...)
	return nil
}

// readFrame reads a single complete FUSE reply frame from the host FD. It
// reassembles the frame from the byte stream using the header's self-describing
// Len, and returns the parsed header plus a newly allocated buffer holding the
// whole frame (header + payload). Bytes read past the frame boundary are
// retained in hc.readBuf for the next frame.
//
// On an invalid Len it returns errBadFrame; the caller must tear the connection
// down rather than attempt to resync, as FUSE stream framing has no resync
// point.
func (hc *hostConnection) readFrame() (linux.FUSEHeaderOut, []byte, error) {
	// Ensure the fixed-size header is fully buffered.
	for uint32(len(hc.readBuf)) < linux.SizeOfFUSEHeaderOut {
		if err := hc.fillReadBuf(); err != nil {
			return linux.FUSEHeaderOut{}, nil, err
		}
	}

	var hdr linux.FUSEHeaderOut
	hdr.UnmarshalUnsafe(hc.readBuf[:linux.SizeOfFUSEHeaderOut])

	if hdr.Len < linux.SizeOfFUSEHeaderOut || uint64(hdr.Len) > hc.maxFrame() {
		return hdr, nil, errBadFrame
	}
	frameLen := int(hdr.Len)

	if len(hc.readBuf) >= frameLen {
		// The whole frame (and possibly the start of the next) is buffered.
		buf := make([]byte, frameLen)
		copy(buf, hc.readBuf)
		if leftover := len(hc.readBuf) - frameLen; leftover > 0 {
			rem := make([]byte, leftover)
			copy(rem, hc.readBuf[frameLen:])
			hc.readBuf = rem
		} else {
			hc.readBuf = hc.readBuf[:0]
		}
		return hdr, buf, nil
	}

	// Only part of the frame is buffered. Read the remainder directly into the
	// frame buffer, bounded by frameLen so we never over-read into the next
	// frame.
	buf := make([]byte, frameLen)
	n := copy(buf, hc.readBuf)
	hc.readBuf = hc.readBuf[:0]
	for n < frameLen {
		r, err := readFD(int(hc.hostFD), buf[n:])
		if err != nil {
			return hdr, nil, err
		}
		if r == 0 {
			return hdr, nil, errReaderClosed
		}
		n += r
	}
	return hdr, buf, nil
}

// readLoop reads FUSE reply frames from the host FD and dispatches them to the
// corresponding callers via the connection's completions map. It exits (tearing
// the connection down) on any read error or an invalid frame.
func (hc *hostConnection) readLoop() {
	for {
		hdr, buf, err := hc.readFrame()
		if err != nil {
			if errors.Is(err, errBadFrame) {
				log.Warningf("fuse host connection: invalid frame length %d (max %d); tearing down connection", hdr.Len, hc.maxFrame())
			} else {
				log.Debugf("fuse host connection: reader exiting: %v", err)
			}
			hc.abortPending()
			return
		}
		hc.dispatchReply(hdr, buf)
	}
}

// dispatchReply routes a single framed reply to its waiting caller. Buffer
// ownership transfers to the future; no payload is copied under conn.mu.
func (hc *hostConnection) dispatchReply(hdr linux.FUSEHeaderOut, buf []byte) {
	// Server-initiated notifications (header Unique == 0, notify code in Error)
	// are not supported on this path: consume and discard.
	if hdr.Unique == 0 {
		log.Warningf("fuse host connection: discarding unsupported server notification (code %d)", hdr.Error)
		return
	}

	hc.conn.mu.Lock()
	fut, ok := hc.conn.completions[hdr.Unique]
	if !ok {
		hc.conn.mu.Unlock()
		// A late reply for a request that was canceled/interrupted and already
		// removed from the map. Drop it.
		log.Debugf("fuse host connection: dropping reply for unknown request %d", hdr.Unique)
		return
	}
	delete(hc.conn.completions, hdr.Unique)
	fut.hdr = &hdr
	fut.data = buf
	select {
	case hc.conn.fullQueueCh <- struct{}{}:
	default:
	}
	hc.conn.numActiveRequests--
	close(fut.ch)
	hc.conn.mu.Unlock()
}

// abortPending tears the connection down and wakes all callers blocked on a
// response, delivering ECONNABORTED. Called when the reader goroutine exits due
// to an error, an invalid frame, or FD closure.
func (hc *hostConnection) abortPending() {
	hc.conn.mu.Lock()
	defer hc.conn.mu.Unlock()
	hc.conn.connected = false
	for id, fut := range hc.conn.completions {
		delete(hc.conn.completions, id)
		hc.conn.numActiveRequests--
		// Synthesize an ECONNABORTED reply header so a caller blocked in
		// resolve() sees an error instead of dereferencing a nil fut.hdr.
		fut.hdr = &linux.FUSEHeaderOut{
			Len:    linux.SizeOfFUSEHeaderOut,
			Error:  -int32(unix.ECONNABORTED),
			Unique: id,
		}
		close(fut.ch)
	}
}

// call implements fuseConn.call. It registers a futureResponse, writes the
// request to the host FD, and blocks until the reader goroutine dispatches
// the matching response.
func (hc *hostConnection) call(ctx context.Context, r *Request) (*Response, error) {
	hc.conn.mu.Lock()
	if !hc.conn.connected {
		hc.conn.mu.Unlock()
		return nil, linuxerr.ECONNABORTED
	}

	// No-reply requests (e.g. FUSE_FORGET) never receive a response, so they
	// must not register a completion or consume an active-request slot: nothing
	// would ever clean them up. Write the request and return. This mirrors the
	// device path, which removes noReply requests from the completions map when
	// it dequeues them (see connection.read).
	if r.noReply {
		hc.conn.mu.Unlock()
		if err := hc.writeRequest(r); err != nil {
			return nil, err
		}
		return nil, nil
	}

	hc.conn.numActiveRequests++
	fut := newFutureResponse(r)
	hc.conn.completions[r.id] = fut
	hc.conn.mu.Unlock()

	if err := hc.writeRequest(r); err != nil {
		hc.conn.mu.Lock()
		delete(hc.conn.completions, r.id)
		hc.conn.numActiveRequests--
		hc.conn.mu.Unlock()
		return nil, err
	}

	return fut.resolve(ctx)
}

// Call makes a request to the server via the host FD and blocks until a
// response is received. It mirrors connection.Call but dispatches through the
// host I/O path.
func (hc *hostConnection) Call(ctx context.Context, r *Request) (*Response, error) {
	if !hc.conn.isInitialized() && r.hdr.Opcode != linux.FUSE_INIT {
		if err := ctx.Block(hc.conn.initializedChan); err != nil {
			return nil, linuxError(err)
		}
	}

	hc.conn.mu.Lock()
	connected := hc.conn.connected
	connInitError := hc.conn.connInitError
	hc.conn.mu.Unlock()

	if !connected {
		return nil, linuxerr.ENOTCONN
	}

	if connInitError {
		return nil, linuxerr.ECONNREFUSED
	}

	return hc.call(ctx, r)
}

// CallAsync makes an async (fire-and-forget) request via the host FD. The
// response is read and discarded.
func (hc *hostConnection) CallAsync(ctx context.Context, r *Request) error {
	r.async = true
	_, err := hc.Call(ctx, r)
	return err
}

// release implements fuseConn.release.
func (hc *hostConnection) release(ctx context.Context) {
	hc.conn.DecRef(ctx)
	unix.Close(int(hc.hostFD))
}

// writeRequest writes a FUSE request to the host FD under writeMu.
func (hc *hostConnection) writeRequest(r *Request) error {
	hc.writeMu.Lock()
	defer hc.writeMu.Unlock()
	data := r.data
	for len(data) > 0 {
		n, err := unix.Write(int(hc.hostFD), data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// InitSend performs the FUSE_INIT handshake synchronously over the host FD.
// After a successful handshake, it starts the background reader goroutine
// for concurrent request processing.
func (hc *hostConnection) InitSend(creds *auth.Credentials, pid uint32, hasSysAdminCap bool) error {
	in := linux.FUSEInitIn{
		Major:        linux.FUSE_KERNEL_VERSION,
		Minor:        linux.FUSE_KERNEL_MINOR_VERSION,
		MaxReadahead: fuseDefaultMaxReadahead,
		Flags:        fuseDefaultInitFlags,
	}

	req := hc.conn.NewRequest(creds, pid, 0, linux.FUSE_INIT, &in)

	if err := hc.writeRequest(req); err != nil {
		return err
	}

	// Read the INIT reply through the same framer the reader goroutine uses, so
	// there is a single wire parser. INIT replies fit the small class.
	hdr, buf, err := hc.readFrame()
	if err != nil {
		return err
	}
	if hdr.Unique != req.hdr.Unique {
		log.Warningf("fuse host connection: unexpected reply during INIT (unique %d, want %d)", hdr.Unique, req.hdr.Unique)
		return linuxerr.EIO
	}

	res := &Response{
		opcode: linux.FUSE_INIT,
		hdr:    hdr,
		data:   buf,
	}

	hc.conn.mu.Lock()
	defer hc.conn.mu.Unlock()
	if err := hc.conn.InitRecv(res, hasSysAdminCap); err != nil {
		return err
	}

	hc.startReader()
	return nil
}
