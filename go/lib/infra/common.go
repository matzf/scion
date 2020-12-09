// Copyright 2018 ETH Zurich, Anapaya Systems
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

package infra

import (
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
)

const (
	// DefaultRPCTimeout is the default silent time SCION RPC Clients will wait
	// for before declaring a timeout. Most RPCs will be subject to an
	// additional context, and the timeout will be the minimum value allowed by
	// the context and this timeout. RPC clients are free to use a different
	// timeout if they have special requirements.
	DefaultRPCTimeout time.Duration = 10 * time.Second
)

type MessageType int

const (
	None MessageType = iota
	IfId
)

func (mt MessageType) String() string {
	switch mt {
	case None:
		return "None"
	case IfId:
		return "IfId"
	default:
		return fmt.Sprintf("Unknown (%d)", mt)
	}
}

// MetricLabel returns the label for metrics for a given message type.
// The postfix for requests is always "req" and for replies and push messages it is always "push".
func (mt MessageType) MetricLabel() string {
	switch mt {
	case None:
		return "none"
	case IfId:
		return "ifid_push"
	default:
		return "unknown_mt"
	}
}

// Verifier is used to verify payloads signed with control-plane PKI
// certificates.
type Verifier interface {
	seg.Verifier
	// WithServer returns a verifier that fetches the necessary crypto
	// objects from the specified server.
	WithServer(server net.Addr) Verifier
	// WithIA returns a verifier that only accepts signatures from the
	// specified IA.
	WithIA(ia addr.IA) Verifier
}
