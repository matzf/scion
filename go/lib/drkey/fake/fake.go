// Copyright 2021 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fake implements a interface for fake DRKey derivation. This is
// intended to serve as a mock interface to program against, in the absence of
// the real DRKey implementation.
// The keys returned here are simply the concatenated inputs used to generate
// them, arbitrarily truncated so they fit the 16-byte key size. In the real
// DRKey implementation, the keys would be created by repeated invocations of a
// PRF (AES).
package fake

import (
	"crypto/aes"
	"encoding/binary"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
)

// KeySize in bytes
const KeySize = aes.BlockSize

type ProtocolType uint8

const (
	ProtocolSCMP ProtocolType = iota
)

// Deriver is the interface for DRKeys that can be locally derived.
type Deriver interface {
	ASToAS(b addr.IA, k []byte)
	ASToHost(b addr.IA, hb net.Addr, k []byte) error
	HostToHost(ha net.Addr, b addr.IA, hb net.Addr, k []byte) error
}

// NewFakeDeriver creates a new fake key deriver, localized to AS a, for the p protocol.
func NewFakeDeriver(a addr.IA, p ProtocolType) Deriver {
	return &deriver{
		ia:       a,
		protocol: p,
	}
}

type deriver struct {
	ia       addr.IA
	protocol ProtocolType
}

func (d *deriver) ASToAS(b addr.IA, k []byte) {
	k[0] = byte(d.protocol)
	k[1] = 1                       // level 1
	writeIATruncated(k[2:5], d.ia) // AS A
	writeIATruncated(k[5:8], b)    // AS B
	zero(k[8:16])                  // room left, using same byte pattern as HostToHost
}

func (d *deriver) ASToHost(b addr.IA, hb net.Addr, k []byte) error {
	k[0] = byte(d.protocol)
	k[1] = 2                       // level 2
	writeIATruncated(k[2:5], d.ia) // AS A
	writeIATruncated(k[5:8], b)    // AS B
	zero(k[8:12])
	writeHostTruncated(k[12:16], hb) // Host H_B
	return nil
}

func (d *deriver) HostToHost(ha net.Addr, b addr.IA, hb net.Addr, k []byte) error {
	k[0] = byte(d.protocol)
	k[1] = 3                         // level 3
	writeIATruncated(k[2:5], d.ia)   // AS A
	writeIATruncated(k[5:8], b)      // AS B
	writeHostTruncated(k[8:12], ha)  // Host H_A
	writeHostTruncated(k[12:16], hb) // Host H_B
	return nil
}

// writeIATruncated writes a 3 byte truncated representation of the IA
func writeIATruncated(b []byte, ia addr.IA) {
	b[0] = byte(ia.I)
	binary.BigEndian.PutUint16(b[1:], uint16(ia.A&0xffff))
}

// writeHostTruncated writes a 4 byte truncated representation of h
func writeHostTruncated(b []byte, h net.Addr) {
	s := h.String()
	copy(b[:4], s[len(s)-4:])
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
