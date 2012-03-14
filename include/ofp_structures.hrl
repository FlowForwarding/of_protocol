%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%%%-----------------------------------------------------------------------------

%%%-----------------------------------------------------------------------------
%%% Common Structures
%%%-----------------------------------------------------------------------------

%% Header on all OpenFlow packets
-define(HEADER_SIZE, 8).
-record(header, {
          version = 3 :: integer(),
          xid :: integer()
         }).

%% Message types
-define(OFPT_HELLO, 0).
-define(OFPT_ERROR, 1).
-define(OFPT_ECHO_REQUEST, 2).
-define(OFPT_ECHO_REPLY, 3).
-define(OFPT_EXPERIMENTER, 4).
-define(OFPT_FEATURES_REQUEST, 5).
-define(OFPT_FEATURES_REPLY, 6).
-define(OFPT_GET_CONFIG_REQUEST, 7).
-define(OFPT_GET_CONFIG_REPLY, 8).
-define(OFPT_SET_CONFIG, 9).
-define(OFPT_PACKET_IN, 10).
-define(OFPT_FLOW_REMOVED, 11).
-define(OFPT_PORT_STATUS, 12).
-define(OFPT_PACKET_OUT, 13).
-define(OFPT_FLOW_MOD, 14).
-define(OFPT_GROUP_MOD, 15).
-define(OFPT_PORT_MOD, 16).
-define(OFPT_TABLE_MOD, 17).
-define(OFPT_STATS_REQUEST, 18).
-define(OFPT_STATS_REPLY, 19).
-define(OFPT_BARRIER_REQUEST, 20).
-define(OFPT_BARRIER_REPLY, 21).
-define(OFPT_QUEUE_GET_CONFIG_REQUEST, 22).
-define(OFPT_QUEUE_GET_CONFIG_REPLY, 23).
-define(OFPT_ROLE_REQUEST, 24).
-define(OFPT_ROLE_REPLY, 25).

%%% Port Structures ------------------------------------------------------------

%% Description of a port
-define(PORT_SIZE, 64).
-record(port, {
          port_no :: integer() | atom(),
          hw_addr :: binary(),
          name :: binary(),
          config = [] :: [atom()],
          state = [] :: [atom()],
          curr = [] :: [atom()],
          advertised = [] :: [atom()],
          supported = [] :: [atom()],
          peer = [] :: [atom()],
          curr_speed = 0 :: integer(),
          max_speed = 0 :: integer()
         }).

%% Flags to indicate behavior of the physical port
-define(OFPPC_PORT_DOWN, 0).
-define(OFPPC_NO_STP, 1).
-define(OFPPC_NO_RECV, 2).
-define(OFPPC_NO_RECV_STP, 3).
-define(OFPPC_NO_FLOOD, 4).
-define(OFPPC_NO_FWD, 5).
-define(OFPPC_NO_PACKET_IN, 6).

%% Current state of the physical port
-define(OFPPS_LINK_DOWN, 0).
-define(OFPPS_BLOCKED, 1).
-define(OFPPS_LIVE, 2).

%% Port numbering; Reserved ports
-define(OFPP_MAX, 16#ffffff00).
-define(OFPP_IN_PORT, 16#fffffff8).
-define(OFPP_TABLE, 16#fffffff9).
-define(OFPP_NORMAL, 16#fffffffa).
-define(OFPP_FLOOD, 16#fffffffb).
-define(OFPP_ALL, 16#fffffffc).
-define(OFPP_CONTROLLER, 16#fffffffd).
-define(OFPP_LOCAL, 16#fffffffe).
-define(OFPP_ANY, 16#ffffffff).

%% Features of ports available in a datapath
-define(OFPPF_10MB_HD, 0).
-define(OFPPF_10MB_FD, 1).
-define(OFPPF_100MB_HD, 2).
-define(OFPPF_100MB_FD, 3).
-define(OFPPF_1GB_HD, 4).
-define(OFPPF_1GB_FD, 5).
-define(OFPPF_10GB_FD, 6).
-define(OFPPF_40GB_FD, 7).
-define(OFPPF_100GB_FD, 8).
-define(OFPPF_1TB_FD, 9).
-define(OFPPF_OTHER, 10).
-define(OFPPF_COPPER, 11).
-define(OFPPF_FIBER, 12).
-define(OFPPF_AUTONEG, 13).
-define(OFPPF_PAUSE, 14).
-define(OFPPF_PAUSE_ASYM, 15).

%%% Queue Structures -----------------------------------------------------------

%% Common description for a queue
-record(queue_prop_header, {
          type :: integer()
         }).

%% Min-Rate queue property description
-record(queue_prop_min_rate, {
          header :: #queue_prop_header{},
          rate :: integer()
         }).

%% Max-Rate queue property description
-record(queue_prop_max_rate, {
          header :: #queue_prop_header{},
          rate :: integer()
         }).

%% Experimenter queue property description
-record(queue_prop_experimenter, {
          header :: #queue_prop_header{},
          experimenter :: integer(),
          data :: binary()
         }).

%% Full description for a queue
-record(packet_queue, {
          queue_id :: integer(),
          port :: integer(),
          properties :: #queue_prop_min_rate{} |
                        #queue_prop_max_rate{} |
                        #queue_prop_experimenter{}
         }).

%%% Flow Match Structures ------------------------------------------------------

-record(oxm_field, {
          class :: atom(),
          field :: atom(),
          has_mask :: boolean(),
          value :: binary(),
          mask :: binary()
         }).

%% OXM Class IDs
-define(OFPXMC_NXM_0, 0).
-define(OFPXMC_NXM_1, 1).
-define(OFPXMC_OPENFLOW_BASIC, 16#8000).
-define(OFPXMC_EXPERIMENTER, 16#ffff).

%% OXM Flow match field types
-define(OFPXMT_OFB_IN_PORT, 0).
-define(OFPXMT_OFB_IN_PHY_PORT, 1).
-define(OFPXMT_OFB_METADATA, 2).
-define(OFPXMT_OFB_ETH_DST, 3).
-define(OFPXMT_OFB_ETH_SRC, 4).
-define(OFPXMT_OFB_ETH_TYPE, 5).
-define(OFPXMT_OFB_VLAN_VID, 6).
-define(OFPXMT_OFB_VLAN_PCP, 7).
-define(OFPXMT_OFB_IP_DSCP, 8).
-define(OFPXMT_OFB_IP_ECN, 9).
-define(OFPXMT_OFB_IP_PROTO, 10).
-define(OFPXMT_OFB_IPV4_SRC, 11).
-define(OFPXMT_OFB_IPV4_DST, 12).
-define(OFPXMT_OFB_TCP_SRC, 13).
-define(OFPXMT_OFB_TCP_DST, 14).
-define(OFPXMT_OFB_UDP_SRC, 15).
-define(OFPXMT_OFB_UDP_DST, 16).
-define(OFPXMT_OFB_SCTP_SRC, 17).
-define(OFPXMT_OFB_SCTP_DST, 18).
-define(OFPXMT_OFB_ICMPV4_TYPE, 19).
-define(OFPXMT_OFB_ICMPV4_CODE, 20).
-define(OFPXMT_OFB_ARP_OP, 21).
-define(OFPXMT_OFB_ARP_SPA, 22).
-define(OFPXMT_OFB_ARP_TPA, 23).
-define(OFPXMT_OFB_ARP_SHA, 24).
-define(OFPXMT_OFB_ARP_THA, 25).
-define(OFPXMT_OFB_IPV6_SRC, 26).
-define(OFPXMT_OFB_IPV6_DST, 27).
-define(OFPXMT_OFB_IPV6_FLABEL, 28).
-define(OFPXMT_OFB_ICMPV6_TYPE, 29).
-define(OFPXMT_OFB_ICMPV6_CODE, 30).
-define(OFPXMT_OFB_IPV6_ND_TARGET, 31).
-define(OFPXMT_OFB_IPV6_ND_SLL, 32).
-define(OFPXMT_OFB_IPV6_ND_TLL, 33).
-define(OFPXMT_OFB_MPLS_LABEL, 34).
-define(OFPXMT_OFB_MPLS_TC, 35).

%% Sizes of OXM fields in bits
-define(IN_PORT_FIELD_LENGTH, 32).
-define(IN_PHY_PORT_FIELD_LENGTH, 32).
-define(METADATA_FIELD_LENGTH, 64).
-define(ETH_DST_FIELD_LENGTH, 48).
-define(ETH_SRC_FIELD_LENGTH, 48).
-define(ETH_TYPE_FIELD_LENGTH, 16).
-define(VLAN_VID_FIELD_LENGTH, 13).
-define(VLAN_PCP_FIELD_LENGTH, 3).
-define(IP_DSCP_FIELD_LENGTH, 6).
-define(IP_ECN_FIELD_LENGTH, 2).
-define(IP_PROTO_FIELD_LENGTH, 8).
-define(IPV4_SRC_FIELD_LENGTH, 32).
-define(IPV4_DST_FIELD_LENGTH, 32).
-define(TCP_SRC_FIELD_LENGTH, 16).
-define(TCP_DST_FIELD_LENGTH, 16).
-define(UDP_SRC_FIELD_LENGTH, 16).
-define(UDP_DST_FIELD_LENGTH, 16).
-define(SCTP_SRC_FIELD_LENGTH, 16).
-define(SCTP_DST_FIELD_LENGTH, 16).
-define(ICMPV4_TYPE_FIELD_LENGTH, 8).
-define(ICMPV4_CODE_FIELD_LENGTH, 8).
-define(ARP_OP_FIELD_LENGTH, 16).
-define(ARP_SPA_FIELD_LENGTH, 32).
-define(ARP_TPA_FIELD_LENGTH, 32).
-define(ARP_SHA_FIELD_LENGTH, 48).
-define(ARP_THA_FIELD_LENGTH, 48).
-define(IPV6_SRC_FIELD_LENGTH, 128).
-define(IPV6_DST_FIELD_LENGTH, 128).
-define(IPV6_FLABEL_FIELD_LENGTH, 20).
-define(ICMPV6_TYPE_FIELD_LENGTH, 8).
-define(ICMPV6_CODE_FIELD_LENGTH, 8).
-define(IPV6_ND_TARGET_FIELD_LENGTH, 128).
-define(IPV6_ND_SLL_FIELD_LENGTH, 48).
-define(IPV6_ND_TLL_FIELD_LENGTH, 48).
-define(MPLS_LABEL_FIELD_LENGTH, 20).
-define(MPLS_TC_FIELD_LENGTH, 3).

%% Fields to match against flows
-define(MATCH_SIZE, 8).
-record(match, {
          type :: atom(),
          oxm_fields = [] :: [#oxm_field{}]
         }).

%% Match type
-define(OFPMT_STANDARD, 0).
-define(OFPMT_OXM, 1).

%%% Flow Instruction Structures ------------------------------------------------



%%% Action Structures ----------------------------------------------------------

%% Output action
-define(ACTION_OUTPUT_SIZE, 16).
-record(action_output, {
          port :: integer() | atom(),
          max_len :: integer() | atom()
         }).

%% Controller max length
-define(OFPCML_MAX, 16#ffe5).
-define(OFPCML_NO_BUFFER, 16#ffff).

%% Group action
-define(ACTION_GROUP_SIZE, 8).
-record(action_group, {
          group_id :: integer()
         }).

%% Set queue action
-define(ACTION_SET_QUEUE_SIZE, 8).
-record(action_set_queue, {
          queue_id :: integer()
         }).

%% Set MPLS TTL action
-define(ACTION_SET_MPLS_TTL_SIZE, 8).
-record(action_set_mpls_ttl, {
          mpls_ttl :: integer()
         }).

%% Decrement MPLS TTL action
-define(ACTION_DEC_MPLS_TTL_SIZE, 8).
-record(action_dec_mpls_ttl, {}).

%% Set IPv4 TTL action
-define(ACTION_SET_NW_TTL_SIZE, 8).
-record(action_set_nw_ttl, {
          nw_ttl :: integer()
         }).

%% Decrement IPv4 TTL action
-define(ACTION_DEC_NW_TTL_SIZE, 8).
-record(action_dec_nw_ttl, {}).

%% Copy TTL outwards action
-define(ACTION_COPY_TTL_OUT_SIZE, 8).
-record(action_copy_ttl_out, {}).

%% Copy TTL inwards action
-define(ACTION_COPY_TTL_IN_SIZE, 8).
-record(action_copy_ttl_in, {}).

%% Push VLAN header action
-define(ACTION_PUSH_VLAN_SIZE, 8).
-record(action_push_vlan, {
          ethertype :: integer()
         }).

%% Pop VLAN header action
-define(ACTION_POP_VLAN_SIZE, 8).
-record(action_pop_vlan, {}).

%% Push MPLS header action
-define(ACTION_PUSH_MPLS_SIZE, 8).
-record(action_push_mpls, {
          ethertype :: integer()
         }).

%% Pop MPLS header action
-define(ACTION_POP_MPLS_SIZE, 8).
-record(action_pop_mpls, {
          ethertype :: integer()
         }).

%% Set field action
-define(ACTION_SET_FIELD_SIZE, 8).
-record(action_set_field, {
          field :: #oxm_field{}
         }).

%% Experimenter action
-define(ACTION_EXPERIMENTER_SIZE, 8).
-record(action_experimenter, {
          experimenter :: integer()
         }).

%% Action types
-define(OFPAT_OUTPUT, 0).
-define(OFPAT_COPY_TTL_OUT, 11).
-define(OFPAT_COPY_TTL_IN, 12).
-define(OFPAT_SET_MPLS_TTL, 15).
-define(OFPAT_DEC_MPLS_TTL, 16).
-define(OFPAT_PUSH_VLAN, 17).
-define(OFPAT_POP_VLAN, 18).
-define(OFPAT_PUSH_MPLS, 19).
-define(OFPAT_POP_MPLS, 20).
-define(OFPAT_SET_QUEUE, 21).
-define(OFPAT_GROUP, 22).
-define(OFPAT_SET_NW_TTL, 23).
-define(OFPAT_DEC_NW_TTL, 24).
-define(OFPAT_SET_FIELD, 25).
-define(OFPAT_EXPERIMENTER, 16#ffff).

-type action() :: #action_output{} | #action_group{} | #action_set_queue{} |
                  #action_set_mpls_ttl{} | #action_dec_mpls_ttl{} |
                  #action_set_nw_ttl{} | #action_dec_nw_ttl{} |
                  #action_copy_ttl_out{} | #action_copy_ttl_in{} |
                  #action_push_vlan{} | #action_pop_vlan{} |
                  #action_push_mpls{} | #action_pop_mpls{} |
                  #action_set_field{} | #action_experimenter{}.
