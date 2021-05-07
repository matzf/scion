// Copyright 2020 Anapaya Systems
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

package slayers

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// OptionType indicates the type of a TLV Option that is part of an extension header.
type OptionType uint8

// Definition of option type constants.
const (
	OptTypePad1 OptionType = iota
	OptTypePadN
	OptTypeAuthenticator
)

type tlvOption struct {
	OptType      OptionType
	OptDataLen   uint8
	ActualLength int
	OptData      []byte
	OptAlign     [2]uint8 // Xn+Y = [2]uint8{X, Y}
}

func (o *tlvOption) length(fixLengths bool) int {
	if o.OptType == OptTypePad1 {
		return 1
	}
	if fixLengths {
		return len(o.OptData) + 2
	}
	return int(o.OptDataLen) + 2
}

func (o *tlvOption) serializeTo(data []byte, fixLengths bool) {
	dryrun := data == nil
	if o.OptType == OptTypePad1 {
		if !dryrun {
			data[0] = 0x0
		}
		return
	}
	if fixLengths {
		o.OptDataLen = uint8(len(o.OptData))
	}
	if !dryrun {
		data[0] = uint8(o.OptType)
		data[1] = o.OptDataLen
		copy(data[2:], o.OptData)
	}
}

func decodeTLVOption(data []byte) (*tlvOption, error) {
	o := &tlvOption{OptType: OptionType(data[0])}
	if OptionType(data[0]) == OptTypePad1 {
		o.ActualLength = 1
		return o, nil
	}
	if len(data) < 2 {
		return nil, serrors.New("buffer too short", "expected", 2, "actual", len(data))
	}
	o.OptDataLen = data[1]
	o.ActualLength = int(o.OptDataLen) + 2
	if len(data) < o.ActualLength {
		return nil, serrors.New("buffer too short", "expected", o.ActualLength, "actual", len(data))
	}
	o.OptData = data[2:o.ActualLength]
	return o, nil
}

// serializeTLVOptionPadding adds an appropriate PadN extension.
func serializeTLVOptionPadding(data []byte, padLength int) {
	if padLength <= 0 {
		return
	}
	if padLength == 1 {
		data[0] = 0x0
		return
	}
	dataLen := uint8(padLength) - 2
	padN := tlvOption{
		OptType:    OptTypePadN,
		OptDataLen: dataLen,
		OptData:    make([]byte, dataLen),
	}
	padN.serializeTo(data, false)
	return
}

// serializeTLVOptions serializes options to buf and returns the length of the serialized options.
// Passing in a nil-buffer will treat the serialization as a dryrun that can be used to calculate
// the length needed for the buffer.
func serializeTLVOptions(buf []byte, options []*tlvOption, fixLengths bool) int {
	dryrun := buf == nil
	// length start at 2 since the padding needs to be calculated taking the first 2 bytes of the
	// extension header (NextHdr and ExtLen fields) into account.
	length := 2
	for _, opt := range options {
		if fixLengths {
			x := int(opt.OptAlign[0])
			y := int(opt.OptAlign[1])
			if x != 0 {
				n := length / x
				offset := x*n + y
				if offset < length {
					offset += x
				}
				if length != offset {
					pad := offset - length
					if !dryrun {
						serializeTLVOptionPadding(buf[length-2:], pad)
					}
					length += pad
				}
			}
		}
		if !dryrun {
			opt.serializeTo(buf[length-2:], fixLengths)
		}
		length += opt.length(fixLengths)
	}
	if fixLengths {
		pad := length % LineLen
		if pad != 0 {
			if !dryrun {
				serializeTLVOptionPadding(buf[length-2:], pad)
			}
			length += pad
		}
	}
	return length - 2
}

type extnBase struct {
	layers.BaseLayer
	NextHdr common.L4ProtocolType
	// ExtLen is the length of the extension header in multiple of 4-bytes NOT including the
	// first 4 bytes.
	ExtLen    uint8
	ActualLen int
}

func (e *extnBase) serializeToWithTLVOptions(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions, tlvOptions []*tlvOption) error {

	l := serializeTLVOptions(nil, tlvOptions, opts.FixLengths)
	bytes, err := b.PrependBytes(l)
	if err != nil {
		return err
	}
	serializeTLVOptions(bytes, tlvOptions, opts.FixLengths)

	length := len(bytes) + 2
	if length%LineLen != 0 {
		return serrors.New("SCION extension actual length must be multiple of 4")
	}
	bytes, err = b.PrependBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = uint8(e.NextHdr)
	if opts.FixLengths {
		e.ExtLen = uint8((length / LineLen) - 1)
	}
	bytes[1] = uint8(e.ExtLen)
	return nil
}

func decodeExtnBase(data []byte, df gopacket.DecodeFeedback) (extnBase, error) {
	e := extnBase{}
	if len(data) < 2 {
		df.SetTruncated()
		return e, serrors.New(fmt.Sprintf("invalid extension header. Length %d less than 2",
			len(data)))
	}
	e.NextHdr = common.L4ProtocolType(data[0])
	e.ExtLen = data[1]
	e.ActualLen = (int(e.ExtLen) + 1) * LineLen
	if len(data) < e.ActualLen {
		return extnBase{}, serrors.New(fmt.Sprintf("invalid extension header. "+
			"Length %d less than specified length %d", len(data), e.ActualLen))
	}
	e.Contents = data[:e.ActualLen]
	e.Payload = data[e.ActualLen:]
	return e, nil
}

// HopByHopOption is a TLV option present in a SCION hop-by-hop extension.
type HopByHopOption tlvOption

// HopByHopExtn is the SCION hop-by-hop options extension.
type HopByHopExtn struct {
	extnBase
	Options []*HopByHopOption
}

func (h *HopByHopExtn) LayerType() gopacket.LayerType {
	return LayerTypeHopByHopExtn
}

func (h *HopByHopExtn) CanDecode() gopacket.LayerClass {
	return LayerTypeHopByHopExtn
}

func (h *HopByHopExtn) NextLayerType() gopacket.LayerType {
	return scionNextLayerType(h.NextHdr)
}

func (h *HopByHopExtn) LayerPayload() []byte {
	return h.Payload
}

// SerializeTo implementation according to gopacket.SerializableLayer
func (h *HopByHopExtn) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	o := make([]*tlvOption, 0, len(h.Options))
	for _, v := range h.Options {
		o = append(o, (*tlvOption)(v))
	}

	return h.extnBase.serializeToWithTLVOptions(b, opts, o)
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (h *HopByHopExtn) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var err error
	h.extnBase, err = decodeExtnBase(data, df)
	if err != nil {
		return err
	}
	offset := 2
	for offset < h.ActualLen {
		opt, err := decodeTLVOption(data[offset:h.ActualLen])
		if err != nil {
			return err
		}
		h.Options = append(h.Options, (*HopByHopOption)(opt))
		offset += opt.ActualLength
	}
	return nil
}

func decodeHopByHopExtn(data []byte, p gopacket.PacketBuilder) error {
	h := &HopByHopExtn{}
	err := h.DecodeFromBytes(data, p)
	p.AddLayer(h)
	if err != nil {
		return err
	}
	return p.NextDecoder(scionNextLayerType(h.NextHdr))
}

// EndToEndOption is a TLV option present in a SCION end-to-end extension.
type EndToEndOption tlvOption

// EndToEndExtn is the SCION end-to-end options extension.
type EndToEndExtn struct {
	extnBase
	Options []*EndToEndOption
}

func (e *EndToEndExtn) LayerType() gopacket.LayerType {
	return LayerTypeEndToEndExtn
}

func (e *EndToEndExtn) CanDecode() gopacket.LayerClass {
	return LayerTypeEndToEndExtn
}

func (e *EndToEndExtn) NextLayerType() gopacket.LayerType {
	return scionNextLayerType(e.NextHdr)
}

func (e *EndToEndExtn) LayerPayload() []byte {
	return e.Payload
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (e *EndToEndExtn) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var err error
	e.extnBase, err = decodeExtnBase(data, df)
	if err != nil {
		return err
	}
	if e.NextHdr == common.HopByHopClass {
		return serrors.New("e2e extension must not come before the HBH extension")
	}
	offset := 2
	for offset < e.ActualLen {
		opt, err := decodeTLVOption(data[offset:e.ActualLen])
		if err != nil {
			return err
		}
		e.Options = append(e.Options, (*EndToEndOption)(opt))
		offset += opt.ActualLength
	}
	return nil
}

func decodeEndToEndExtn(data []byte, p gopacket.PacketBuilder) error {
	e := &EndToEndExtn{}
	err := e.DecodeFromBytes(data, p)
	p.AddLayer(e)
	if err != nil {
		return err
	}
	return p.NextDecoder(scionNextLayerType(e.NextHdr))
}

// SerializeTo implementation according to gopacket.SerializableLayer
func (e *EndToEndExtn) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	if e.NextHdr == common.HopByHopClass {
		return serrors.New("e2e extension must not come before the HBH extension")
	}

	o := make([]*tlvOption, 0, len(e.Options))
	for _, v := range e.Options {
		o = append(o, (*tlvOption)(v))
	}

	return e.extnBase.serializeToWithTLVOptions(b, opts, o)
}

// FindAuthenticator returns the Authenticator option header, if any exists.
// Returns an error if no authenticator header was found or if it is malformed (zero length).
// The authenticator data slice returned points to the underlying buffer and
// should not be modified by the caller. The data is not checked in any form,
// the caller is responsible for checking the length and interpreting the data.
// Only returns the first entry with this type, subsequent entries will be
// ignored.
func (e *EndToEndExtn) FindAuthenticator() (EndToEndAuthenticatorAlgorithm, []byte, error) {
	for _, o := range e.Options {
		if o.OptType == OptTypeAuthenticator {
			return o.parseOptAuthenticator()
		}
	}
	return 0, nil, serrors.New("no authenticator option")
}

type EndToEndAuthenticatorAlgorithm uint8

const (
	E2EAuthCMAC       EndToEndAuthenticatorAlgorithm = 0
	E2EAuthGMAC       EndToEndAuthenticatorAlgorithm = 1
	E2EAuthHMACSHA256 EndToEndAuthenticatorAlgorithm = 16
	E2EAuthEd25519    EndToEndAuthenticatorAlgorithm = 32
)

// MakeAuthenticator initializes o as an OptTypeAuthenticator option.
// If the capacity of the OptData buffer is large enough, it will be overwritten.
func (o *EndToEndOption) MakeAuthenticator(alg EndToEndAuthenticatorAlgorithm, data []byte) {
	o.OptType = OptTypeAuthenticator

	n := 1 + len(data)
	if n <= cap(o.OptData) {
		o.OptData = o.OptData[:n]
	} else {
		o.OptData = make([]byte, n)
	}
	o.OptData[0] = byte(alg)
	copy(o.OptData[1:], data)

	o.OptAlign = [2]uint8{4, 1}
	// reset unused/implicit fields
	o.OptDataLen = 0
	o.ActualLength = 0
}

// parseOptAuthenticator parses o as an OptTypeAuthenticator option.
// OptType must be OptTypeAuthenticator.
func (o *EndToEndOption) parseOptAuthenticator() (EndToEndAuthenticatorAlgorithm, []byte, error) {
	if o.OptType != OptTypeAuthenticator {
		panic("type must be OptTypeAuthenticator")
	}
	if len(o.OptData) < 2 {
		return 0, nil, serrors.New("buffer too short", "expected", 2, "actual", len(o.OptData))
	}
	alg := EndToEndAuthenticatorAlgorithm(o.OptData[0])
	data := o.OptData[1:]
	return alg, data, nil
}
