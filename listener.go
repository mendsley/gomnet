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
	"bytes"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"net"
	"sync"
	"time"
)

var ErrListenerClosed = errors.New("Listener has been closed")

type listener struct {
	sync.Cond
	err           error
	addr          net.Addr
	pending       []net.Conn
	stopListening func()
}

// Listen announces on the local network address laddr.
// The network net must be a packet-oriented netowrk:
// "udp", "udp4", "udp6", "unixgram".
func Listen(network, addr string) (net.Listener, error) {
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}
	return ListenConn(conn)
}

// Listen announces on existing packet-based connection
func ListenConn(conn net.PacketConn) (net.Listener, error) {
	l := &listener{
		Cond: sync.Cond{
			L: new(sync.Mutex),
		},
		addr: conn.LocalAddr(),
	}

	rld := &receiveLoopData{
		Cond: sync.Cond{
			L: new(sync.Mutex),
		},
		buffers: [][]byte{
			make([]byte, 65536),
			make([]byte, 65536),
			make([]byte, 65536),
		},
	}

	pld := &processLoopData{
		Cond: sync.Cond{
			L: new(sync.Mutex),
		},
	}

	l.stopListening = func() {
		pld.L.Lock()
		pld.rejectNewConnections = true
		pld.L.Unlock()
		pld.Signal()
	}

	go receiveLoop(conn, l, rld, pld)
	go processLoop(conn, l, rld, pld)
	return l, nil
}

// Close the listener. Stops accepting new
// connections, but will continue to process
// established connections.
func (l *listener) Close() error {
	l.L.Lock()
	err := l.err
	if err == nil {
		l.err = ErrListenerClosed
	}
	l.L.Unlock()
	l.Broadcast()

	if err == nil {
		l.stopListening()
	}

	return errors.New("Not implemented")
}

// Accept blocks until a new connection is ready,
// then returns that connection to the caller.
func (l *listener) Accept() (net.Conn, error) {
	l.L.Lock()
	defer l.L.Unlock()

	for l.err == nil && len(l.pending) == 0 {
		l.Wait()
	}

	if l.err != nil {
		return nil, l.err
	}

	c := l.pending[0]
	n := copy(l.pending, l.pending[1:])
	l.pending = l.pending[:n]

	return c, nil
}

// Addr returns the local address for the listener.
func (l *listener) Addr() net.Addr {
	return l.addr
}

type receiveLoopData struct {
	sync.Cond
	buffers [][]byte
}

// receives datagrams from a connection and enqueues them to
// the processing loop
func receiveLoop(c net.PacketConn, l *listener, rld *receiveLoopData, pld *processLoopData) {
	// wait for a buffer to be available
	for {
		rld.L.Lock()
		for len(rld.buffers) == 0 {
			rld.Wait()
		}

		n := len(rld.buffers)
		buffer := rld.buffers[n-1]
		rld.buffers = rld.buffers[:n-1]
		rld.L.Unlock()

		n, addr, err := c.ReadFrom(buffer[:cap(buffer)])
		if err != nil {
			l.L.Lock()
			if l.err == nil {
				l.err = err
			}
			l.L.Unlock()
			l.Broadcast()

			// notify the processing loop
			pld.L.Lock()
			pld.err = err
			pld.L.Unlock()
			pld.Signal()
			return
		}

		if n < 4 {
			continue
		}

		// push the packet to the processing loop
		pld.L.Lock()
		pld.Q = append(pld.Q, processLoopPacket{D: buffer[:n], A: addr})
		pld.L.Unlock()
		pld.Signal()
	}
}

type processLoopPacket struct {
	D []byte
	A net.Addr
}
type processLoopData struct {
	sync.Cond
	err                  error
	rejectNewConnections bool
	remainingConnections int
	Q                    []processLoopPacket
}

// receives packets from the receive loop and dispatches them
// to their corresponding connections
func processLoop(c net.PacketConn, l *listener, rld *receiveLoopData, pld *processLoopData) {

	var (
		quit        bool
		wg          = new(sync.WaitGroup)
		tq          = newTimerQueue()
		connections = struct {
			sync.RWMutex
			M map[uint32]*connection
		}{
			M: make(map[uint32]*connection),
		}
	)

	// keep a refcount to `c` for ourselves
	wg.Add(1)
	defer wg.Done()

	// wait for all pending connections, then close the socket
	go func() {
		wg.Wait()
		c.Close()
		tq.Close()
	}()

	// generate a new key for cookies
	cookieKey := make([]byte, sha1.Size)
	if _, err := crand.Read(cookieKey); err != nil {
		l.L.Lock()
		l.err = fmt.Errorf("Failed to generate cookie secret: %v", err)
		l.L.Unlock()
		l.Broadcast()
		return
	}

	sig := hmac.New(sha1.New, cookieKey)

	// generate addler32(localaddr)
	var localAddrSum [4]byte
	binary.LittleEndian.PutUint32(localAddrSum[:], adler32.Checksum([]byte(c.LocalAddr().String())))

	shouldWait := func() bool {
		waitOnConnections := pld.rejectNewConnections && pld.remainingConnections == 0
		return pld.err == nil && len(pld.Q) == 0 && !waitOnConnections
	}

	var packets []processLoopPacket

	for !quit {
		// wait for a packet to become available
		pld.L.Lock()
		for shouldWait() {
			pld.Wait()
		}
		rejectNewConnections := pld.rejectNewConnections
		pldErr := pld.err
		quit = pldErr != nil
		packets, pld.Q = pld.Q, packets[:0]
		remainingConnections := pld.remainingConnections
		pld.L.Unlock()

		if rejectNewConnections && remainingConnections == 0 {
			quit = true
		}

		// process packets
		for ii := range packets {
			buffer, addr := packets[ii].D, packets[ii].A

			switch PacketType(buffer[0]) {
			case PacketInit:
				// are we accepting new connections?
				if rejectNewConnections {
					continue
				}

				// verify length
				const MinInitPacketLength = 9
				if len(buffer) < MinInitPacketLength {
					continue
				}

				// verify protocol magic
				if !bytes.Equal(buffer[1:5], protocolMagic) {
					continue
				}

				// verify version
				if buffer[5] != version1 {
					sendAbort(c, addr, buffer[6:9])
					continue
				}

				var outgoing [32]byte
				now := time.Now()
				outgoing[0] = byte(PacketCookie)
				if _, err := crand.Read(outgoing[1:4]); err != nil {
					return
				}
				copy(outgoing[4:7], buffer[6:9])
				outgoing[7] = version1
				binary.LittleEndian.PutUint32(outgoing[8:12], uint32(now.Add(5*time.Second).Unix()+1))

				sig.Reset()
				sig.Write(outgoing[1:12])
				sig.Write(localAddrSum[:])
				sig.Sum(outgoing[1:12])
				c.WriteTo(outgoing[:], addr)

			case PacketCookieEcho:

				// are we accepting new connections
				if rejectNewConnections {
					continue
				}

				// verify length
				const CookieEchoPacketLength = 32
				if len(buffer) != CookieEchoPacketLength {
					continue
				}

				// verify signature
				sig.Reset()
				sig.Write(buffer[1:12])
				sig.Write(localAddrSum[:])
				if !hmac.Equal(sig.Sum(nil), buffer[12:]) {
					continue
				}

				// verify version
				if buffer[7] != version1 {
					sendAbort(c, addr, buffer[1:4])
					continue
				}

				// vetify timeout
				now := time.Now()
				if time.Unix(int64(binary.LittleEndian.Uint32(buffer[8:12])), 0).Before(now) {
					sendAbort(c, addr, buffer[1:4])
					continue
				}

				// decode connection tag to uin32
				tagId := binary.LittleEndian.Uint32(buffer[3:7]) >> 8

				connections.RLock()
				_, ok := connections.M[tagId]
				connections.RUnlock()
				// create new connection
				if !ok {

					// create connection
					wg.Add(1)
					connections.Lock()
					conn := newConnection(c, addr, tq, buffer[1:4], func() {
						connections.Lock()
						delete(connections.M, tagId)
						connections.Unlock()

						wg.Done()

						pld.L.Lock()
						pld.remainingConnections--
						remain := pld.remainingConnections
						pld.L.Unlock()

						if remain == 0 {
							pld.Signal()
						}
					})

					connections.M[tagId] = conn
					connections.Unlock()

					pld.L.Lock()
					pld.remainingConnections++
					pld.L.Unlock()

					l.L.Lock()
					l.pending = append(l.pending, conn)
					l.L.Unlock()
					l.Signal()
				}

				// send COOKIE-ACK
				var outgoing [4]byte
				outgoing[0] = byte(PacketCookieAck)
				copy(outgoing[1:4], buffer[1:4])
				c.WriteTo(outgoing[:], addr)

			default:
				// parse connection tag
				tagId := binary.LittleEndian.Uint32(buffer[0:4]) >> 8
				connections.RLock()
				conn, ok := connections.M[tagId]
				connections.RUnlock()

				// discard packets addressed to unknown connections
				if !ok {
					sendAbort(c, addr, buffer[1:4])
					continue
				}

				// copy the packet data so we can reuse the buffer
				p := NewPacket(len(buffer))
				copy(p.D, buffer)

				// queue the packet onto the connection
				conn.L.Lock()
				conn.Incoming = append(conn.Incoming, p)
				conn.L.Unlock()
				conn.Signal()
			}
		}

		// return the packet to the receive loop
		rld.L.Lock()
		for ii := range packets {
			rld.buffers = append(rld.buffers, packets[ii].D)
		}
		rld.L.Unlock()
		rld.Signal()

		// if we were signaled to quit, terminate existing connections
		if pldErr != nil {
			connections.Lock()
			m := connections.M
			connections.M = make(map[uint32]*connection)
			connections.Unlock()

			for _, c := range m {
				c.closeWithError(pldErr)
			}
		}
	}
}

// sends an ABORT packet to the specified peer
func sendAbort(c net.PacketConn, addr net.Addr, tag []byte) {
	p := NewPacket(4)
	p.D[0] = byte(PacketAbort)
	copy(p.D[1:4], tag)
	c.WriteTo(p.D, addr)
	p.Free()
}
