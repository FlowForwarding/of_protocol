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
%% @copyright 2012 FlowForwarding.org
%% @doc OpenFlow Protocol 1.2 (3) mappings.
%% @private
-module(ofp_v3_map).

-export([tlv_length/1]).

-include("of_protocol.hrl").
-include("ofp_v3.hrl").

%% @doc Get field's length in bits.
-spec tlv_length(atom()) -> integer().
tlv_length(in_port)        -> ?IN_PORT_FIELD_LENGTH;
tlv_length(in_phy_port)    -> ?IN_PHY_PORT_FIELD_LENGTH;
tlv_length(metadata)       -> ?METADATA_FIELD_LENGTH;
tlv_length(eth_dst)        -> ?ETH_DST_FIELD_LENGTH;
tlv_length(eth_src)        -> ?ETH_SRC_FIELD_LENGTH;
tlv_length(eth_type)       -> ?ETH_TYPE_FIELD_LENGTH;
tlv_length(vlan_vid)       -> ?VLAN_VID_FIELD_LENGTH;
tlv_length(vlan_pcp)       -> ?VLAN_PCP_FIELD_LENGTH;
tlv_length(ip_dscp)        -> ?IP_DSCP_FIELD_LENGTH;
tlv_length(ip_ecn)         -> ?IP_ECN_FIELD_LENGTH;
tlv_length(ip_proto)       -> ?IP_PROTO_FIELD_LENGTH;
tlv_length(ipv4_src)       -> ?IPV4_SRC_FIELD_LENGTH;
tlv_length(ipv4_dst)       -> ?IPV4_DST_FIELD_LENGTH;
tlv_length(tcp_src)        -> ?TCP_SRC_FIELD_LENGTH;
tlv_length(tcp_dst)        -> ?TCP_DST_FIELD_LENGTH;
tlv_length(udp_src)        -> ?UDP_SRC_FIELD_LENGTH;
tlv_length(udp_dst)        -> ?UDP_DST_FIELD_LENGTH;
tlv_length(sctp_src)       -> ?SCTP_SRC_FIELD_LENGTH;
tlv_length(sctp_dst)       -> ?SCTP_DST_FIELD_LENGTH;
tlv_length(icmpv4_type)    -> ?ICMPV4_TYPE_FIELD_LENGTH;
tlv_length(icmpv4_code)    -> ?ICMPV4_CODE_FIELD_LENGTH;
tlv_length(arp_op)         -> ?ARP_OP_FIELD_LENGTH;
tlv_length(arp_spa)        -> ?ARP_SPA_FIELD_LENGTH;
tlv_length(arp_tpa)        -> ?ARP_TPA_FIELD_LENGTH;
tlv_length(arp_sha)        -> ?ARP_SHA_FIELD_LENGTH;
tlv_length(arp_tha)        -> ?ARP_THA_FIELD_LENGTH;
tlv_length(ipv6_src)       -> ?IPV6_SRC_FIELD_LENGTH;
tlv_length(ipv6_dst)       -> ?IPV6_DST_FIELD_LENGTH;
tlv_length(ipv6_flabel)    -> ?IPV6_FLABEL_FIELD_LENGTH;
tlv_length(icmpv6_type)    -> ?ICMPV6_TYPE_FIELD_LENGTH;
tlv_length(icmpv6_code)    -> ?ICMPV6_CODE_FIELD_LENGTH;
tlv_length(ipv6_nd_target) -> ?IPV6_ND_TARGET_FIELD_LENGTH;
tlv_length(ipv6_nd_sll)    -> ?IPV6_ND_SLL_FIELD_LENGTH;
tlv_length(ipv6_nd_tll)    -> ?IPV6_ND_TLL_FIELD_LENGTH;
tlv_length(mpls_label)     -> ?MPLS_LABEL_FIELD_LENGTH;
tlv_length(mpls_tc)        -> ?MPLS_TC_FIELD_LENGTH.
