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
	crand "crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	ErrBadAddress    = errors.New("Bad peer address")
	ErrNotPacketConn = errors.New("Not a packet connection network")
	ErrConnectFailed = errors.New("Connection to remote peer failed")
)

// Connects to a remote host
// The network net must be a packet-oriented netowrk:
// "udp", "udp4", "udp6", "unixgram".
func Dial(network, address string) (net.Conn, error) {
	pc, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, err
	}

	var addr net.Addr
	switch network {
	case "udp", "udp4", "udp6":
		addr, err = net.ResolveUDPAddr(network, address)
	case "unix", "unixgram", "unixpacket":
		addr, err = net.ResolveUnixAddr(network, address)
	default:
		return nil, ErrBadAddress
	}
	if err != nil {
		return nil, err
	}

	return NewConn(pc, addr)
}

func NewConn(pc net.PacketConn, addr net.Addr) (net.Conn, error) {

	// gerenate outgoing connection tag
	var outgoingTag [3]byte
	if _, err := crand.Read(outgoingTag[:]); err != nil {
		pc.Close()
		return nil, fmt.Errorf("Failed to generate connection tag: %v", err)
	}

	// generate INIT packet
	initPacket := NewPacket(9)
	initPacket.D[0] = byte(PacketInit)
	copy(initPacket.D[1:5], protocolMagic)
	initPacket.D[5] = version1
	copy(initPacket.D[6:9], outgoingTag[:])

	// send INIT packet
	retries := 5
	buffer := make([]byte, 65536)
	for {
		_, err := pc.WriteTo(initPacket.D, addr)
		if err != nil {
			pc.Close()
			return nil, err
		}

		// wait for a response
		pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := pc.ReadFrom(buffer[:cap(buffer)])
		pc.SetReadDeadline(time.Time{})
		if ne, ok := err.(net.Error); ok && ne.Timeout() && ne.Temporary() {
			n = 0
		} else if err != nil {
			pc.Close()
			return nil, err
		}

		// did we get a cookie packet?
		buffer = buffer[:n]
		if n >= 8 {
			if PacketType(buffer[0]) == PacketCookie && bytes.Equal(outgoingTag[:], buffer[4:7]) && buffer[7] == version1 {
				break
			}
		}

		retries--
		if retries == 0 {
			pc.Close()
			return nil, ErrConnectFailed
		}
	}
	initPacket.Free()

	// buffer now holds the cookie packet. Switch it to COOKIE-ECHO
	cookiePacket := NewPacket(len(buffer))
	cookiePacket.D[0] = byte(PacketCookieEcho)
	copy(cookiePacket.D[1:], buffer[1:])

	// extract the association tag from the COOKIE packet
	var incomingTag [3]byte
	copy(incomingTag[:], buffer[1:4])

	// send COOKIE-ECHO packet
	retries = 5
	for {
		_, err := pc.WriteTo(cookiePacket.D, addr)
		if err != nil {
			pc.Close()
			return nil, err
		}

		// wait for a response
		pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := pc.ReadFrom(buffer[:cap(buffer)])
		pc.SetReadDeadline(time.Time{})
		if ne, ok := err.(net.Error); ok && ne.Timeout() && ne.Temporary() {
			n = 0
		} else if err != nil {
			pc.Close()
			return nil, err
		}

		// did we get a COOKIE-ACK packet?
		buffer = buffer[:n]
		if n == 4 {
			if PacketType(buffer[0]) == PacketCookieAck && bytes.Equal(buffer[1:4], incomingTag[:]) {
				break
			}
		}

		retries--
		if retries == 0 {
			pc.Close()
			return nil, ErrConnectFailed
		}
	}
	cookiePacket.Free()

	// create connection
	conn := newConnection(pc, addr, newTimerQueue(), outgoingTag[:], func() { pc.Close() })

	// start read loop
	go client_receiveLoop(pc, conn, incomingTag, buffer)
	return conn, nil
}

// receive packets and feed them to the connection
func client_receiveLoop(c net.PacketConn, conn *connection, incomingTag [3]byte, buffer []byte) {
	for {
		n, _, err := c.ReadFrom(buffer[:cap(buffer)])
		if err != nil {
			conn.Close()
			return
		}

		if n >= 4 && bytes.Equal(buffer[1:4], incomingTag[:]) {
			pkt := NewPacket(n)
			copy(pkt.D, buffer[:n])
			conn.L.Lock()
			conn.Incoming = append(conn.Incoming, pkt)
			conn.L.Unlock()
			conn.Signal()
		}
	}
}
