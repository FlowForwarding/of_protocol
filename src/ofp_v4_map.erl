%%------------------------------------------------------------------------------
%% Copyright 2012 FlowForwarding.org
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%-----------------------------------------------------------------------------

%% @author Erlang Solutions Ltd. <openflow@erlang-solutions.com>
%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%% @author Konrad Kaplita <konrad.kaplita@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org
%% @doc OpenFlow Protocol 1.3 (4) mappings.
%% @private
-module(ofp_v4_map).

-export([tlv_length/1]).
-export([tlv_wire_length/1]).

-include("of_protocol.hrl").
-include("ofp_v4.hrl").

%% @doc Get field's length in bits.
%% From OpenFlow 1.3 spec page 44.
-spec tlv_length(atom()) -> integer().
tlv_length(in_port)        -> 32;
tlv_length(in_phy_port)    -> 32;
tlv_length(metadata)       -> 64;
tlv_length(eth_dst)        -> 48;
tlv_length(eth_src)        -> 48;
tlv_length(eth_type)       -> 16;
tlv_length(vlan_vid)       -> 13;
tlv_length(vlan_pcp)       -> 3;
tlv_length(ip_dscp)        -> 6;
tlv_length(ip_ecn)         -> 2;
tlv_length(ip_proto)       -> 8;
tlv_length(ipv4_src)       -> 32;
tlv_length(ipv4_dst)       -> 32;
tlv_length(tcp_src)        -> 16;
tlv_length(tcp_dst)        -> 16;
tlv_length(udp_src)        -> 16;
tlv_length(udp_dst)        -> 16;
tlv_length(sctp_src)       -> 16;
tlv_length(sctp_dst)       -> 16;
tlv_length(icmpv4_type)    -> 8;
tlv_length(icmpv4_code)    -> 8;
tlv_length(arp_op)         -> 16;
tlv_length(arp_spa)        -> 32;
tlv_length(arp_tpa)        -> 32;
tlv_length(arp_sha)        -> 48;
tlv_length(arp_tha)        -> 48;
tlv_length(ipv6_src)       -> 128;
tlv_length(ipv6_dst)       -> 128;
tlv_length(ipv6_flabel)    -> 20;
tlv_length(icmpv6_type)    -> 8;
tlv_length(icmpv6_code)    -> 8;
tlv_length(ipv6_nd_target) -> 128;
tlv_length(ipv6_nd_sll)    -> 48;
tlv_length(ipv6_nd_tll)    -> 48;
tlv_length(mpls_label)     -> 20;
tlv_length(mpls_tc)        -> 3;
tlv_length(mpls_bos)       -> 1;
tlv_length(pbb_isid)       -> 24;
tlv_length(tunnel_id)      -> 64;
tlv_length(ipv6_exthdr)    -> 9;
%% ---BEGIN--- LINC-OE
tlv_length(odu_sigtype)    -> 8;
tlv_length(odu_sigid)      -> 8;
tlv_length(och_sigtype)    -> 8;
tlv_length(och_sigid)      -> 48;
%% ---END--- LINC-OE
tlv_length(poc_timestamp1) -> 64;
tlv_length(poc_timestamp2) -> 64.

%% @doc Get field's on-wire length in bits.
%%
%% NOTE: While the spec defines ipv6_flabel and mpls_label as 20-bit,
%% ONF openflow.h defines them as 32-bit.  Other implementations seem
%% to agree with 32-bit.  (Open vSwitch, Ryu, ofsoftswitch13, ...)
%% Unfortunately ONF doesn't seem to publish openflow.h.
%% Ben Pfaff kindly made it available at http://benpfaff.org/ofh/.
-spec tlv_wire_length(atom()) -> integer().
tlv_wire_length(ipv6_flabel) -> 32;
tlv_wire_length(mpls_label) -> 32;
tlv_wire_length(Type) -> tlv_length(Type).
