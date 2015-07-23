// Copyright 2014-2015 Matthew Endsley
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted providing that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package mnet

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	ErrConnectionReset  = errors.New("Connection has been reset")
	ErrConnectionClosed = errors.New("Connection has been closed")
	ErrReadTimeout      = errors.New("Read operation timeout")
)

const shutdownTimeout = 3 * time.Second

type connectionState int

const (
	connectionActive = connectionState(iota)
	connectionAbort
	connectionClosed
	connectionShutdownPending
	connectionShutdownReceived
	connectionShutdownSent
	connectionShutdownAckSent
)

type connection struct {
	sync.Cond
	WriteErr error
	ReadErr  error
	Incoming []Packet
	Outgoing []Packet

	addr      net.Addr
	localAddr net.Addr

	closeCalled bool
	closeWait   chan struct{}
	readData    struct {
		sync.Mutex
		sync.WaitGroup
		timeout time.Time
		p       []byte
		pn      *int
	}
}

func newConnection(c net.PacketConn, addr net.Addr, tq *timerQueue, tag []byte, closed func()) *connection {
	conn := &connection{
		Cond:      sync.Cond{L: new(sync.Mutex)},
		addr:      addr,
		localAddr: c.LocalAddr(),
		closeWait: make(chan struct{}),
	}

	var tag3 [3]byte
	copy(tag3[:], tag)
	go conn.proc(c, tq, tag3, closed)
	return conn
}

func (c *connection) Close() error {
	c.L.Lock()
	alreadySent := c.closeCalled
	c.closeCalled = true
	c.L.Unlock()

	if !alreadySent {
		c.Signal()
	}

	<-c.closeWait
	c.L.Lock()
	err := c.ReadErr
	c.L.Unlock()
	if err == io.EOF {
		err = nil
	}
	return err
}

func (c *connection) closeWithError(err error) error {
	c.L.Lock()
	if c.ReadErr == nil {
		c.ReadErr = err
	}
	if c.WriteErr == nil {
		c.WriteErr = err
	}
	c.L.Unlock()

	return c.Close()
}

func (c *connection) Read(p []byte) (int, error) {
	// only allow one active Read call at a time
	c.readData.Lock()
	defer c.readData.Unlock()

	var (
		n   int
		err error
	)
	for n == 0 && err == nil {
		c.L.Lock()
		err = c.ReadErr
		if err == nil {
			c.readData.p = p
			c.readData.pn = &n
			c.readData.Add(1)
		}
		c.L.Unlock()

		if err == nil {
			c.Signal()
			c.readData.Wait()
		}
	}

	return n, err
}

func (c *connection) Write(p []byte) (int, error) {
	n := 0
	c.L.Lock()
	err := c.WriteErr
	if err == nil && len(p) > 0 {
		pkt := NewPacket(len(p))
		n = copy(pkt.D, p)
		c.Outgoing = append(c.Outgoing, pkt)
	}
	c.L.Unlock()
	if err == nil && len(p) > 0 {
		c.Signal()
	}
	return n, err
}

func (c *connection) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *connection) RemoteAddr() net.Addr {
	return c.addr
}

func (c *connection) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	err2 := c.SetWriteDeadline(t)
	if err == nil {
		err = err2
	}

	return err
}

func (c *connection) SetReadDeadline(t time.Time) error {
	c.L.Lock()
	c.readData.timeout = t
	if c.ReadErr == ErrReadTimeout {
		c.ReadErr = nil
	}
	c.L.Unlock()
	c.Signal()
	return nil
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *connection) proc(pc net.PacketConn, tq *timerQueue, connectionTag [3]byte, closed func()) {
	defer close(c.closeWait)
	defer closed()

	data := &connectionData{
		RetransmitTimer: timer{
			Cond: &c.Cond,
		},
		ConnectionTag: connectionTag,
	}
	abortTimer := timer{
		Cond: &c.Cond,
	}

	state := connectionActive
	for state != connectionClosed {
		switch state {
		case connectionActive:
			state = c.state_active(pc, tq, data)
		case connectionShutdownPending:
			state = c.state_shutdownPending(pc, tq, &abortTimer, data)
		case connectionShutdownReceived:
			state = c.state_shutdownReceived(pc, tq, &abortTimer, data)
		case connectionShutdownSent:
			state = c.state_shutdownSent(pc, tq, &abortTimer, data)
		case connectionShutdownAckSent:
			state = c.state_shutdownAckSent(pc, tq, &abortTimer, data)
		case connectionAbort:
			state = c.state_abort(pc, connectionTag)

		default:
			panic("unkown state: " + strconv.FormatInt(int64(state), 10))
		}
	}
}

// deliver pending data to the application
func (c *connection) deliverApplicationData(cd *connectionData) {
	// is there data to deliver
	if len(cd.ApplicationData) == 0 {
		return
	}

	// is there an active Read call?
	c.L.Lock()
	p, pn := c.readData.p, c.readData.pn
	c.L.Unlock()
	if p == nil {
		return
	}

	// deliver as much data as possible
	next := p
	n := 0
	for len(next) > 0 {
		if len(cd.ApplicationData) == 0 {
			break
		}

		p := cd.ApplicationData[0]
		read := copy(next, p.D)
		p.D = p.D[read:]
		cd.ApplicationData[0].D = p.D
		next = next[read:]
		n += read

		// purge fully delivered packet
		if len(p.D) == 0 {
			p.Free()
			m := copy(cd.ApplicationData, cd.ApplicationData[1:])
			cd.ApplicationData = cd.ApplicationData[:m]
		}
	}

	// remove the pending read
	c.L.Lock()
	c.readData.p = nil
	c.L.Unlock()

	// unblock Read call
	*pn = n
	c.readData.Done()
}

// determines if the connection can deliver data to an active Read call.
// Requires c.L to be held
func (c *connection) locked_canDeliverData(cd *connectionData) bool {
	return c.readData.p != nil && len(cd.ApplicationData) != 0
}

// determines if the read timeout has expired
func (c *connection) locked_readOperationTimedOut(tq *timerQueue, cd *connectionData) bool {
	return !c.readData.timeout.IsZero() && tq.Now().After(c.readData.timeout)
}

// determines if the connection needs to wait for something to do
func (c *connection) shouldWaitOnCV(tq *timerQueue, cd *connectionData) bool {
	return len(c.Incoming) == 0 &&
		len(c.Outgoing) == 0 &&
		!cd.RetransmitTimer.Signaled() &&
		!c.locked_canDeliverData(cd) &&
		!c.locked_readOperationTimedOut(tq, cd)
}

// process the ACTIVE state
func (c *connection) state_active(pc net.PacketConn, tq *timerQueue, cd *connectionData) connectionState {

	var (
		incoming, outgoing []Packet
		prevTimeout        time.Time
		readTimeout        = timer{
			Cond: &c.Cond,
		}
	)

	for {
		// wait for something to do
		c.L.Lock()
		for c.shouldWaitOnCV(tq, cd) && !c.closeCalled && c.readData.timeout.Equal(prevTimeout) {
			c.Wait()
		}
		newTimeout := c.readData.timeout
		closeCalled := c.closeCalled
		incoming = append(incoming, c.Incoming...)
		outgoing = append(outgoing, c.Outgoing...)
		c.Incoming, c.Outgoing = c.Incoming[:0], c.Outgoing[:0]

		// did the read operation timeout?
		readTimedout := c.locked_readOperationTimedOut(tq, cd)
		if readTimedout {
			if c.ReadErr == nil {
				c.ReadErr = ErrReadTimeout
			}

			readTimedout = c.readData.p != nil // need an unblock?
			c.readData.p = nil
			c.readData.timeout = time.Time{}
		}

		c.L.Unlock()

		// need to unblock a timedout Read?
		if readTimedout {
			tq.StopTimer(&readTimeout)
			c.readData.Done()
		}

		// Start new read timeout
		if !newTimeout.Equal(prevTimeout) {
			prevTimeout = newTimeout
			tq.StopTimer(&readTimeout)
			if !newTimeout.IsZero() {
				d := newTimeout.Sub(tq.Now())
				if d > 0 {
					tq.StartTimer(&readTimeout, d)
				}
			}
		}

		// process client data and release packets
		err := cd.Process(pc, c.addr, tq, incoming, outgoing)
		for _, p := range incoming {
			p.Free()
		}
		for _, p := range outgoing {
			p.Free()
		}
		incoming, outgoing = incoming[:0], outgoing[:0]

		// process any failures
		if err != nil {
			c.L.Lock()
			c.ReadErr = err
			c.WriteErr = err
			c.L.Unlock()
			return connectionAbort
		}

		// deliver any application data
		c.deliverApplicationData(cd)

		// it's an error to receive a SHUTDOWN-ACK packet here
		if cd.ReceivedShutdownAck {
			c.L.Lock()
			c.ReadErr = ProtocolPacketError{Type: PacketShutdownAck}
			c.WriteErr = c.ReadErr
			c.L.Unlock()
			return connectionAbort
		}

		// received a Close() notification
		if closeCalled {
			return connectionShutdownPending
		}

		if cd.ReceivedShutdown {
			return connectionShutdownReceived
		}
	}
}

// process the connection state SHUTDOWN-PENDING
func (c *connection) state_shutdownPending(pc net.PacketConn, tq *timerQueue, timerAbort *timer, cd *connectionData) connectionState {

	// get last set of packets to send
	c.L.Lock()
	c.WriteErr = ErrConnectionClosed
	outgoing := c.Outgoing
	c.Outgoing = nil
	c.L.Unlock()

	// start the abort timer
	tq.StartTimer(timerAbort, shutdownTimeout)

	var incoming []Packet
	for {
		var timerAborted, allDataAcked bool
		c.L.Lock()
		for c.shouldWaitOnCV(tq, cd) {
			timerAborted = timerAbort.Signaled()
			allDataAcked = len(outgoing) == 0 && cd.AllDataAcked()
			if timerAborted || allDataAcked {
				break
			}
			c.Wait()
		}
		c.Outgoing = nil
		incoming = append(incoming, c.Incoming...)
		c.Incoming = c.Incoming[:0]
		c.L.Unlock()

		// if we've expired the abort timer, bail out
		if timerAborted {
			return connectionAbort
		}

		// has alll data been acknowleged?
		if allDataAcked {
			return connectionShutdownSent
		}

		// process client data and release packets
		err := cd.Process(pc, c.addr, tq, incoming, outgoing)
		for _, p := range incoming {
			p.Free()
		}
		for _, p := range outgoing {
			p.Free()
		}
		incoming, outgoing = incoming[:0], nil

		if err != nil {
			c.L.Lock()
			c.ReadErr = err
			c.WriteErr = err
			c.L.Unlock()
			return connectionAbort
		}

		// deliver application data
		c.deliverApplicationData(cd)
	}
}

// process the connection state SHUTDOWN-RECVEIVED
func (c *connection) state_shutdownReceived(pc net.PacketConn, tq *timerQueue, timerAbort *timer, cd *connectionData) connectionState {

	// get last set of packets to send
	c.L.Lock()
	c.WriteErr = ErrConnectionClosed
	outgoing := c.Outgoing
	c.Outgoing = nil
	c.L.Unlock()

	// start the abort timer
	tq.StartTimer(timerAbort, shutdownTimeout)

	var incoming []Packet
	for {
		var timerAborted, allDataAcked bool
		c.L.Lock()
		for c.shouldWaitOnCV(tq, cd) {
			timerAborted = timerAbort.Signaled()
			allDataAcked = len(outgoing) == 0 && cd.AllDataAcked()
			if timerAborted || allDataAcked {
				break
			}
			c.Wait()
		}
		c.Outgoing = nil
		incoming = append(incoming, c.Incoming...)
		c.Incoming = c.Incoming[:0]
		c.L.Unlock()

		// if we've expired the abort timer, bail out
		if timerAborted {
			return connectionAbort
		}

		// has alll data been acknowleged and delivered?
		if allDataAcked && len(cd.ApplicationData) == 0 {
			return connectionShutdownAckSent
		}

		// process client data and release packets
		err := cd.Process(pc, c.addr, tq, incoming, outgoing)
		for _, p := range incoming {
			p.Free()
		}
		for _, p := range outgoing {
			p.Free()
		}
		incoming, outgoing = incoming[:0], nil

		if err != nil {
			c.L.Lock()
			c.ReadErr = err
			c.WriteErr = err
			c.L.Unlock()
			return connectionAbort
		}

		// deliver application data
		c.deliverApplicationData(cd)
	}
}

// process the connection state SHUTDOWN-SENT
func (c *connection) state_shutdownSent(pc net.PacketConn, tq *timerQueue, abortTimer *timer, cd *connectionData) connectionState {

	// no longer ACK data
	cd.DisableAcks = true

	// disable T2-rtx
	tq.StopTimer(&cd.RetransmitTimer)
	retransmit := timer{
		Cond: &c.Cond,
	}

	var (
		currentAck = cd.AcknowlegedBytes() - 1
		incoming   []Packet
	)

	retransmitsLeft := 5
	for {
		// if we have a new outgoing sequence, (re)send SHUTDOWN packet
		if seq := cd.AcknowlegedBytes(); seq != currentAck || retransmit.Signaled() {
			// process resends of the SHUTDOWN packet
			if seq == currentAck {
				retransmitsLeft--
				if retransmitsLeft <= 0 {
					return connectionAbort
				}
			}

			// build SHUTDOWN packet
			currentAck = cd.AcknowlegedBytes()
			p := NewPacket(8)
			p.D[0] = byte(PacketShutdown)
			copy(p.D[1:4], cd.ConnectionTag[:])
			binary.LittleEndian.PutUint32(p.D[4:8], currentAck)

			// Send to peer
			_, err := pc.WriteTo(p.D, c.addr)
			if err != nil {
				c.L.Lock()
				c.ReadErr = err
				c.WriteErr = err
				c.L.Unlock()
				return connectionAbort
			}

			// Start T2-rtx to resend SHUTDOWN
			tq.StopTimer(&retransmit)
			tq.StartTimer(&retransmit, 400*time.Millisecond)
		}

		// wait for connection to become ready
		timerAborted, receivedShutdown := false, false
		c.L.Lock()
		for c.shouldWaitOnCV(tq, cd) && !retransmit.Signaled() {
			timerAborted = abortTimer.Signaled()
			receivedShutdown = cd.ReceivedShutdown
			if timerAborted || receivedShutdown {
				break
			}

			c.Wait()
		}
		incoming = append(incoming, c.Incoming...)
		c.Incoming = c.Incoming[:0]
		c.L.Unlock()

		// on SHUTDOWN, transition to SHUTDOWN-ACK-SENT
		if cd.ReceivedShutdown {
			return connectionShutdownAckSent
		}

		// on SHUTDOWN-ACK, transition to CLOSED
		if cd.ReceivedShutdownAck {
			// Read now returns io.EOF
			c.L.Lock()
			if c.ReadErr == nil {
				c.ReadErr = io.EOF
			}
			unblockRead := c.readData.p != nil
			c.readData.p = nil
			c.L.Unlock()
			if unblockRead {
				c.readData.Done()
			}

			// send SHUTDOWN-COMPLETE
			p := NewPacket(4)
			p.D[0] = byte(PacketShutdownComplete)
			copy(p.D[1:4], cd.ConnectionTag[:])
			pc.WriteTo(p.D, c.addr)

			return connectionClosed
		}

		if timerAborted {
			return connectionAbort
		}

		// process incoming data
		err := cd.Process(pc, c.addr, tq, incoming, nil)
		for _, p := range incoming {
			p.Free()
		}
		incoming = incoming[:0]
		if err != nil {
			c.L.Lock()
			c.ReadErr = err
			c.WriteErr = err
			c.L.Unlock()
			return connectionAbort
		}

		// deliver application data
		c.deliverApplicationData(cd)
	}
}

// process the connection state SHUTDOWN-ACK-SENT
func (c *connection) state_shutdownAckSent(pc net.PacketConn, tq *timerQueue, abortTimer *timer, cd *connectionData) connectionState {

	// Read now returns io.EOF
	c.L.Lock()
	if c.ReadErr == nil {
		c.ReadErr = io.EOF
	}
	unblockRead := c.readData.p != nil
	c.readData.p = nil
	c.L.Unlock()

	if unblockRead {
		c.readData.Done()
	}

	// no longer ACK data
	cd.DisableAcks = true

	// disable T2-rtx
	tq.StopTimer(&cd.RetransmitTimer)

	var (
		incoming        []Packet
		first           = true
		retransmitsLeft = 5

		retransmit = timer{
			Cond: &c.Cond,
		}
	)

	for {
		// retransmit SHUTDOWN-ACK packet
		if first || retransmit.Signaled() {
			first = false
			// process resends of the SHUTDOWN packet
			retransmitsLeft--
			if retransmitsLeft <= 0 {
				return connectionAbort
			}

			// build SHUTDOWN packet
			p := NewPacket(4)
			p.D[0] = byte(PacketShutdownAck)
			copy(p.D[1:4], cd.ConnectionTag[:])

			// Send to peer
			_, err := pc.WriteTo(p.D, c.addr)
			if err != nil {
				c.L.Lock()
				c.ReadErr = err
				c.WriteErr = err
				c.L.Unlock()
				return connectionAbort
			}

			// Start T2-rtx to resend SHUTDOWN-ACK
			tq.StopTimer(&retransmit)
			tq.StartTimer(&retransmit, 400*time.Millisecond)
		}

		// wait for connection to become ready
		c.L.Lock()
		for len(c.Incoming) == 0 && !retransmit.Signaled() && !abortTimer.Signaled() {
			c.Wait()
		}
		incoming = append(incoming, c.Incoming...)
		c.Incoming = c.Incoming[:0]
		c.L.Unlock()

		// has the abort timer been signaled
		if abortTimer.Signaled() {
			return connectionAbort
		}

		// have we found a SHUTDOWN-COMPLETE packet?
		shutdownComplete := false
		for _, p := range incoming {
			if PacketType(p.D[0]) == PacketShutdownComplete {
				shutdownComplete = true
			}
			p.Free()
		}

		// on SHUTDOWN-COMPLETE, transition to CLOSED
		if shutdownComplete {
			return connectionClosed
		}
	}
}

// process the connection state ABORT
func (c *connection) state_abort(pc net.PacketConn, connectionTag [3]byte) connectionState {

	// signal connection as aborted
	c.L.Lock()
	outgoing, incoming := c.Outgoing, c.Incoming
	c.Outgoing, c.Incoming = nil, nil
	if c.WriteErr == nil {
		c.WriteErr = ErrConnectionReset
	}
	if c.ReadErr == nil {
		c.ReadErr = ErrConnectionReset
	}
	unblockRead := c.readData.p != nil
	c.readData.p = nil
	c.L.Unlock()

	// free any remaining outgoing/incoming data
	for _, p := range outgoing {
		p.Free()
	}
	for _, p := range incoming {
		p.Free()
	}

	// unblock pending Read call
	if unblockRead {
		c.readData.Done()
	}

	// send ABORT to the peer
	sendAbort(pc, c.addr, connectionTag[:])
	return connectionClosed
}
