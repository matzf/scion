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

package cases

import (
	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/integration/braccept/runner"
	"github.com/scionproto/scion/go/lib/slayers"
)

func scmpNormalizePacket(pkt gopacket.Packet) {
	// Apply all the standard normalizations.
	runner.DefaultNormalizePacket(pkt)
	normalizePacketAuthOption(pkt)
}

// normalizePacketAuthOption zeros out the MAC in the packet authenticator
// option. The MAC includes the current timestamp added by the sender and so
// cannot be predicted.
// TODO(matzf) Also zero timestamp once this is actually added.
func normalizePacketAuthOption(pkt gopacket.Packet) {
	e2e := pkt.Layer(slayers.LayerTypeEndToEndExtn)
	if e2e == nil {
		return
	}
	opt, err := e2e.(*slayers.EndToEndExtn).FindOption(slayers.OptTypeAuthenticator)
	if err != nil {
		return
	}
	optAuth, err := slayers.ParsePacketAuthenticatorOption(opt)
	if err != nil {
		return
	}
	auth := optAuth.Authenticator()
	for i := range auth {
		auth[i] = 0
	}
}
