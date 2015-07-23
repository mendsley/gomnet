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
	"fmt"
	"net"
	"time"
)

const (
	retransmitTimeout        = 200 * time.Millisecond
	maxSequentialRetransmits = 15
)

var (
	ErrBadProcolPacket     = errors.New("Unexpected packet from peer")
	ErrBadDataPacketLength = errors.New("Bad peer DATA packet length")
	ErrPeerAckedUnsentData = errors.New("Peer acked unsent data")
	ErrPeerNotResponding   = errors.New("Peer not responding to traffic")
)

type ProtocolPacketError struct {
	Type PacketType
}

func (err ProtocolPacketError) Error() string {
	return fmt.Sprintf("Unexpected packet %d from peer", err.Type)
}

// Manages data stream for a peer connection
type connectionData struct {
	RetransmitTimer     timer    // T2-rtx
	ApplicationData     []Packet // Data ready to be delivered to application
	ReceivedShutdown    bool     // Have we received a SHUTDOWN packet
	ReceivedShutdownAck bool     // Have we received a SHUTDOWN-ACK packet
	DisableAcks         bool     // Can we automatically ACK data?
	ConnectionTag       [3]byte  // Connection tag to identify the peer

	pendingAck        []Packet // Packets awaiting ACK from peer
	outgoingSequence  uint32   // bytes our peer has acknowledged
	bytesReceived     uint32   // bytes we have received
	timerSequenceWait int      // timerSequence at the point StartTimer was called
	timerSequence     int      // incremented each time the timer is stopped
	retransmits       int      // sequential retransmits without data from the peer
}

type writeTo interface {
	WriteTo(p []byte, addr net.Addr) (int, error)
}

// Process incoming/outgoing packets for a connection's data channel
func (cd *connectionData) Process(c writeTo, addr net.Addr, tq *timerQueue, incoming, outgoing []Packet) error {
	// add new data to the pending-ack list
	cd.pendingAck = append(cd.pendingAck, outgoing...)
	for _, p := range outgoing {
		p.Addref()
	}

	retransmitSignaled := cd.RetransmitTimer.Signaled()

	sendAck, err := cd.processIncoming(tq, incoming)
	if err != nil {
		return err
	}

	sendData := len(cd.pendingAck) > 0 && !cd.RetransmitTimer.Active()

	// update resend logic
	if len(incoming) != 0 {
		cd.retransmits = 0
	} else if retransmitSignaled {
		cd.retransmits++
		if cd.retransmits > maxSequentialRetransmits {
			return ErrPeerNotResponding
		}
	}

	// do we need to send a packet to the peer?
	if !cd.DisableAcks {
		if sendAck || sendData {
			return cd.sendOutgoingPacket(c, addr, tq)
		}
	}

	return nil
}

// Returns `true` if all outstanding data has been acknowledged
func (cd *connectionData) AllDataAcked() bool {
	return len(cd.pendingAck) == 0
}

// Returnes the total number of acknowleged bytes so far
func (cd *connectionData) AcknowlegedBytes() uint32 {
	return cd.bytesReceived
}

// Process incoming packets from the peer. Update the reliable data as
// necessary and queue application data to `cd.ApplicationData`. Returns
// `true` if an acknowledgment needs to be sent to the peer.
func (cd *connectionData) processIncoming(tq *timerQueue, incoming []Packet) (bool, error) {
	needsAck := false
	for _, p := range incoming {
		switch typ := PacketType(p.D[0]); typ {
		case PacketData:
			if len(p.D) < 14 {
				return false, fmt.Errorf("Short DATA length: %d", len(p.D)) //ErrBadDataPacketLength
			}

			clientBytes := binary.LittleEndian.Uint16(p.D[12:14])
			if len(p.D) != 14+int(clientBytes) {
				return false, fmt.Errorf("Mismatched DATA packet %d %d", len(p.D), 14+int(clientBytes)) //ErrBadDataPacketLength
			}

			if clientBytes > 0 {
				needsAck = true
			}

			// ACK data sent to peer
			incomingAck := binary.LittleEndian.Uint32(p.D[8:12])
			if err := cd.flushAckedData(incomingAck); err != nil {
				return false, err
			}

			// skip out-of-order packets
			incomingSequence := binary.LittleEndian.Uint32(p.D[4:8])
			diff := int64(incomingSequence) - int64(cd.bytesReceived+uint32(clientBytes))
			if diff == 0 {
				// stop the T2-rtx timer
				tq.StopTimer(&cd.RetransmitTimer)
				cd.timerSequence++
				cd.bytesReceived = incomingSequence

				// copy the packet to the pending application queue
				p.D = p.D[14:]
				if len(p.D) > 0 {
					p.Addref()
					cd.ApplicationData = append(cd.ApplicationData, p)
				}
			}

		case PacketShutdown:
			if len(p.D) == 8 {
				cd.ReceivedShutdown = true
				incomingAck := binary.LittleEndian.Uint32(p.D[4:8])
				if err := cd.flushAckedData(incomingAck); err != nil {
					return false, err
				}
			}

		case PacketShutdownAck:
			cd.ReceivedShutdownAck = true
		case PacketAbort:
			return false, ErrConnectionReset

		default:
			return false, ProtocolPacketError{Type: typ}
		}
	}

	return needsAck, nil
}

// Flush all pending-ACK data up through the specified incoming ACK
func (cd *connectionData) flushAckedData(incomingAck uint32) error {
	remainingBytesToAck := incomingAck - cd.outgoingSequence
	for remainingBytesToAck > 0 {
		// if we don't havbe a pending packet to ACK, then we've
		// encountered a protocol error. The peer has acked more
		// data than we've sent
		if len(cd.pendingAck) == 0 {
			return ErrPeerAckedUnsentData
		}

		// ack bytes from first packets
		p := cd.pendingAck[0]
		bytesToAck := remainingBytesToAck
		if nn := uint32(len(p.D)); bytesToAck > nn {
			bytesToAck = nn
		}

		n := copy(p.D, p.D[bytesToAck:])
		cd.pendingAck[0].D = p.D[:n]

		// acked entire packet?
		if n == 0 {
			p.Free()
			n := copy(cd.pendingAck, cd.pendingAck[1:])
			cd.pendingAck = cd.pendingAck[:n]
		}

		remainingBytesToAck -= bytesToAck
		cd.outgoingSequence += bytesToAck
	}

	return nil
}

// Build and send a DATA packet to the peer. This will acknowledge received
// data as well as transmit application data to the peer.
func (cd *connectionData) sendOutgoingPacket(c writeTo, addr net.Addr, tq *timerQueue) error {
	// fill header fields that are not dependent on packet data
	p := NewPacket(14)
	p.D[0] = byte(PacketData)
	copy(p.D[1:4], cd.ConnectionTag[:])
	binary.LittleEndian.PutUint32(p.D[8:12], cd.bytesReceived)

	const maxDatagramSize = 512

	// append data until we have a full packet
	var clientBytes uint16
	remaining := maxDatagramSize - len(p.D)
	for _, out := range cd.pendingAck {
		if remaining == 0 {
			break
		}

		dataToWrite := len(out.D)
		if dataToWrite > remaining {
			dataToWrite = remaining
		}

		p.D = append(p.D, out.D[:dataToWrite]...)
		clientBytes += uint16(dataToWrite)
		remaining -= dataToWrite
	}

	// fill header fields that are dependent on packet data
	binary.LittleEndian.PutUint32(p.D[4:8], cd.outgoingSequence+uint32(clientBytes))
	binary.LittleEndian.PutUint16(p.D[12:14], clientBytes)
	if 14+int(clientBytes) != len(p.D) {
		panic(fmt.Sprintf("Malformed data length. %d != %d", clientBytes, len(p.D)))
	}

	// send the packet to the peer
	_, err := c.WriteTo(p.D, addr)
	p.Free()

	// (re)start the retransmit timer
	if clientBytes > 0 {
		tq.StopTimer(&cd.RetransmitTimer)
		tq.StartTimer(&cd.RetransmitTimer, retransmitTimeout)
		cd.timerSequence++
		cd.timerSequenceWait = cd.timerSequence
	}

	return err
}
