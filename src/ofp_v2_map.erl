%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc Module for mapping between atoms and bits for OFP 1.1.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_v2_map).

%% Helper functions
-export([get_experimenter_bit/1]).

%% Mapping functions
-export([msg_type/1]).
-export([port_config/1,
         port_state/1,
         encode_port_no/1,
         decode_port_no/1,
         port_feature/1]).
-export([encode_queue_id/1,
         decode_queue_id/1,
         queue_property/1]).
-export([match_type/1,
         flow_wildcard/1]).
-export([instruction_type/1]).
-export([action_type/1,
         action_set_type/1]).
-export([capability/1]).
-export([configuration/1]).
-export([flow_command/1,
         flow_flag/1,
         encode_buffer_id/1,
         decode_buffer_id/1]).
-export([encode_table_id/1,
         decode_table_id/1,
         encode_group_id/1,
         decode_group_id/1]).

-include("of_protocol.hrl").
-include("ofp_v2.hrl").

%%%-----------------------------------------------------------------------------
%%% Common Structure
%%%-----------------------------------------------------------------------------

%%% Header ---------------------------------------------------------------------

msg_type(hello)                          -> ?OFPT_HELLO;
msg_type(?OFPT_HELLO)                    -> hello;
msg_type(error)                          -> ?OFPT_ERROR;
msg_type(?OFPT_ERROR)                    -> error;
msg_type(echo_request)                   -> ?OFPT_ECHO_REQUEST;
msg_type(?OFPT_ECHO_REQUEST)             -> echo_request;
msg_type(echo_reply)                     -> ?OFPT_ECHO_REPLY;
msg_type(?OFPT_ECHO_REPLY)               -> echo_reply;
msg_type(experimenter)                   -> ?OFPT_EXPERIMENTER;
msg_type(?OFPT_EXPERIMENTER)             -> experimenter;
msg_type(features_request)               -> ?OFPT_FEATURES_REQUEST;
msg_type(?OFPT_FEATURES_REQUEST)         -> features_request;
msg_type(features_reply)                 -> ?OFPT_FEATURES_REPLY;
msg_type(?OFPT_FEATURES_REPLY)           -> features_reply;
msg_type(get_config_request)             -> ?OFPT_GET_CONFIG_REQUEST;
msg_type(?OFPT_GET_CONFIG_REQUEST)       -> get_config_request;
msg_type(get_config_reply)               -> ?OFPT_GET_CONFIG_REPLY;
msg_type(?OFPT_GET_CONFIG_REPLY)         -> get_config_reply;
msg_type(set_config)                     -> ?OFPT_SET_CONFIG;
msg_type(?OFPT_SET_CONFIG)               -> set_config;
msg_type(packet_in)                      -> ?OFPT_PACKET_IN;
msg_type(?OFPT_PACKET_IN)                -> packet_in;
msg_type(flow_removed)                   -> ?OFPT_FLOW_REMOVED;
msg_type(?OFPT_FLOW_REMOVED)             -> flow_removed;
msg_type(port_status)                    -> ?OFPT_PORT_STATUS;
msg_type(?OFPT_PORT_STATUS)              -> port_status;
msg_type(packet_out)                     -> ?OFPT_PACKET_OUT;
msg_type(?OFPT_PACKET_OUT)               -> packet_out;
msg_type(flow_mod)                       -> ?OFPT_FLOW_MOD;
msg_type(?OFPT_FLOW_MOD)                 -> flow_mod;
msg_type(group_mod)                      -> ?OFPT_GROUP_MOD;
msg_type(?OFPT_GROUP_MOD)                -> group_mod;
msg_type(port_mod)                       -> ?OFPT_PORT_MOD;
msg_type(?OFPT_PORT_MOD)                 -> port_mod;
msg_type(table_mod)                      -> ?OFPT_TABLE_MOD;
msg_type(?OFPT_TABLE_MOD)                -> table_mod;
msg_type(stats_request)                  -> ?OFPT_STATS_REQUEST;
msg_type(?OFPT_STATS_REQUEST)            -> stats_request;
msg_type(stats_reply)                    -> ?OFPT_STATS_REPLY;
msg_type(?OFPT_STATS_REPLY)              -> stats_reply;
msg_type(barrier_request)                -> ?OFPT_BARRIER_REQUEST;
msg_type(?OFPT_BARRIER_REQUEST)          -> barrier_request;
msg_type(barrier_reply)                  -> ?OFPT_BARRIER_REPLY;
msg_type(?OFPT_BARRIER_REPLY)            -> barrier_reply;
msg_type(queue_get_config_request)       -> ?OFPT_QUEUE_GET_CONFIG_REQUEST;
msg_type(?OFPT_QUEUE_GET_CONFIG_REQUEST) -> queue_get_config_request;
msg_type(queue_get_config_reply)         -> ?OFPT_QUEUE_GET_CONFIG_REPLY;
msg_type(?OFPT_QUEUE_GET_CONFIG_REPLY)   -> queue_get_config_reply;
msg_type(Int) when is_integer(Int)       -> throw({bad_value, Int}).

%%% Port Structures ------------------------------------------------------------

port_config(port_down)                  -> ?OFPPC_PORT_DOWN;
port_config(?OFPPC_PORT_DOWN)           -> port_down;
port_config(no_recv)                    -> ?OFPPC_NO_RECV;
port_config(?OFPPC_NO_RECV)             -> no_recv;
port_config(no_fwd)                     -> ?OFPPC_NO_FWD;
port_config(?OFPPC_NO_FWD)              -> no_fwd;
port_config(no_packet_in)               -> ?OFPPC_NO_PACKET_IN;
port_config(?OFPPC_NO_PACKET_IN)        -> no_packet_in;
port_config(Type) when is_atom(Type)    -> throw({bad_type, Type});
port_config(Type) when is_integer(Type) -> throw({bad_value, Type}).

port_state(link_down)                  -> ?OFPPS_LINK_DOWN;
port_state(?OFPPS_LINK_DOWN)           -> link_down;
port_state(blocked)                    -> ?OFPPS_BLOCKED;
port_state(?OFPPS_BLOCKED)             -> blocked;
port_state(live)                       -> ?OFPPS_LIVE;
port_state(?OFPPS_LIVE)                -> live;
port_state(Type) when is_atom(Type)    -> throw({bad_type, Type});
port_state(Type) when is_integer(Type) -> throw({bad_value, Type}).

encode_port_no(in_port)                  -> ?OFPP_IN_PORT;
encode_port_no(table)                    -> ?OFPP_TABLE;
encode_port_no(normal)                   -> ?OFPP_NORMAL;
encode_port_no(flood)                    -> ?OFPP_FLOOD;
encode_port_no(all)                      -> ?OFPP_ALL;
encode_port_no(controller)               -> ?OFPP_CONTROLLER;
encode_port_no(local)                    -> ?OFPP_LOCAL;
encode_port_no(any)                      -> ?OFPP_ANY;
encode_port_no(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_port_no(Int) when is_integer(Int) -> Int.

decode_port_no(?OFPP_IN_PORT)            -> in_port;
decode_port_no(?OFPP_TABLE)              -> table;
decode_port_no(?OFPP_NORMAL)             -> normal;
decode_port_no(?OFPP_FLOOD)              -> flood;
decode_port_no(?OFPP_ALL)                -> all;
decode_port_no(?OFPP_CONTROLLER)         -> controller;
decode_port_no(?OFPP_LOCAL)              -> local;
decode_port_no(?OFPP_ANY)                -> any;
decode_port_no(Int) when is_integer(Int) -> Int.

port_feature('10mb_hd')                  -> ?OFPPF_10MB_HD;
port_feature(?OFPPF_10MB_HD)             -> '10mb_hd';
port_feature('10mb_fd')                  -> ?OFPPF_10MB_FD;
port_feature(?OFPPF_10MB_FD)             -> '10mb_fd';
port_feature('100mb_hd')                 -> ?OFPPF_100MB_HD;
port_feature(?OFPPF_100MB_HD)            -> '100mb_hd';
port_feature('100mb_fd')                 -> ?OFPPF_100MB_FD;
port_feature(?OFPPF_100MB_FD)            -> '100mb_fd';
port_feature('1gb_hd')                   -> ?OFPPF_1GB_HD;
port_feature(?OFPPF_1GB_HD)              -> '1gb_hd';
port_feature('1gb_fd')                   -> ?OFPPF_1GB_FD;
port_feature(?OFPPF_1GB_FD)              -> '1gb_fd';
port_feature('10gb_fd')                  -> ?OFPPF_10GB_FD;
port_feature(?OFPPF_10GB_FD)             -> '10gb_fd';
port_feature('40gb_fd')                  -> ?OFPPF_40GB_FD;
port_feature(?OFPPF_40GB_FD)             -> '40gb_fd';
port_feature('100gb_fd')                 -> ?OFPPF_100GB_FD;
port_feature(?OFPPF_100GB_FD)            -> '100gb_fd';
port_feature('1tb_fd')                   -> ?OFPPF_1TB_FD;
port_feature(?OFPPF_1TB_FD)              -> '1tb_fd';
port_feature(other)                      -> ?OFPPF_OTHER;
port_feature(?OFPPF_OTHER)               -> other;
port_feature(copper)                     -> ?OFPPF_COPPER;
port_feature(?OFPPF_COPPER)              -> copper;
port_feature(fiber)                      -> ?OFPPF_FIBER;
port_feature(?OFPPF_FIBER)               -> fiber;
port_feature(autoneg)                    -> ?OFPPF_AUTONEG;
port_feature(?OFPPF_AUTONEG)             -> autoneg;
port_feature(pause)                      -> ?OFPPF_PAUSE;
port_feature(?OFPPF_PAUSE)               -> pause;
port_feature(pause_asym)                 -> ?OFPPF_PAUSE_ASYM;
port_feature(?OFPPF_PAUSE_ASYM)          -> pause_asym;
port_feature(Type) when is_atom(Type)    -> throw({bad_type, Type});
port_feature(Type) when is_integer(Type) -> throw({bad_value, Type}).

%%% Queue Structures -----------------------------------------------------------

encode_queue_id(all)                      -> ?OFPQ_ALL;
encode_queue_id(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_queue_id(Int) when is_integer(Int) -> Int.

decode_queue_id(?OFPQ_ALL)               -> all;
decode_queue_id(Int) when is_integer(Int) -> Int.

queue_property(min_rate)                   -> ?OFPQT_MIN_RATE;
queue_property(?OFPQT_MIN_RATE)            -> min_rate;
queue_property(Type) when is_integer(Type) -> throw({bad_value, Type}).

%%% Flow Match Structures ------------------------------------------------------

match_type(standard)                   -> ?OFPMT_STANDARD;
match_type(?OFPMT_STANDARD)            -> standard;
match_type(Type) when is_atom(Type)    -> throw({bad_type, Type});
match_type(Type) when is_integer(Type) -> throw({bad_value, Type}).

flow_wildcard(in_port)                    -> ?OFPFW_IN_PORT;
flow_wildcard(?OFPFW_IN_PORT)             -> in_port;
flow_wildcard(vlan_vid)                   -> ?OFPFW_DL_VLAN;
flow_wildcard(?OFPFW_DL_VLAN)             -> vlan_vid;
flow_wildcard(vlan_pcp)                   -> ?OFPFW_DL_VLAN_PCP;
flow_wildcard(?OFPFW_DL_VLAN_PCP)         -> vlan_pcp;
flow_wildcard(eth_type)                   -> ?OFPFW_DL_TYPE;
flow_wildcard(?OFPFW_DL_TYPE)             -> eth_type;
flow_wildcard(ip_dscp)                    -> ?OFPFW_NW_TOS;
flow_wildcard(?OFPFW_NW_TOS)              -> ip_dscp;
flow_wildcard(ip_proto)                   -> ?OFPFW_NW_PROTO;
flow_wildcard(?OFPFW_NW_PROTO)            -> ip_proto;
flow_wildcard(tcp_src)                    -> ?OFPFW_TP_SRC;
flow_wildcard(tcp_dst)                    -> ?OFPFW_TP_DST;
flow_wildcard(udp_src)                    -> ?OFPFW_TP_SRC;
flow_wildcard(udp_dst)                    -> ?OFPFW_TP_DST;
flow_wildcard(sctp_src)                   -> ?OFPFW_TP_SRC;
flow_wildcard(sctp_dst)                   -> ?OFPFW_TP_DST;
flow_wildcard(mpls_label)                 -> ?OFPFW_MPLS_LABEL;
flow_wildcard(?OFPFW_MPLS_LABEL)          -> mpls_label;
flow_wildcard(mpls_tc)                    -> ?OFPFW_MPLS_TC;
flow_wildcard(?OFPFW_MPLS_TC)             -> mpls_tc;
flow_wildcard(Type) when is_atom(Type)    -> throw({bad_type, Type});
flow_wildcard(Type) when is_integer(Type) -> throw({bad_value, Type}).

%%% Flow Instruction Structures ------------------------------------------------

instruction_type(goto_table)                 -> ?OFPIT_GOTO_TABLE;
instruction_type(?OFPIT_GOTO_TABLE)          -> goto_table;
instruction_type(write_metadata)             -> ?OFPIT_WRITE_METADATA;
instruction_type(?OFPIT_WRITE_METADATA)      -> write_metadata;
instruction_type(write_actions)              -> ?OFPIT_WRITE_ACTIONS;
instruction_type(?OFPIT_WRITE_ACTIONS)       -> write_actions;
instruction_type(apply_actions)              -> ?OFPIT_APPLY_ACTIONS;
instruction_type(?OFPIT_APPLY_ACTIONS)       -> apply_actions;
instruction_type(clear_actions)              -> ?OFPIT_CLEAR_ACTIONS;
instruction_type(?OFPIT_CLEAR_ACTIONS)       -> clear_actions;
instruction_type(experimenter)               -> ?OFPIT_EXPERIMENTER;
instruction_type(?OFPIT_EXPERIMENTER)        -> experimenter;
instruction_type(?OFPIT_EXPERIMENTER_BIT)    -> experimenter;
instruction_type(Type) when is_atom(Type)    -> throw({bad_type, Type});
instruction_type(Type) when is_integer(Type) -> throw({bad_value, Type}).

%%% Action Structures ----------------------------------------------------------

action_type(output)                     -> ?OFPAT_OUTPUT;
action_type(?OFPAT_OUTPUT)              -> output;
action_type(?OFPAT_SET_VLAN_VID)        -> set_field;
action_type(?OFPAT_SET_VLAN_PCP)        -> set_field;
action_type(?OFPAT_SET_DL_SRC)          -> set_field;
action_type(?OFPAT_SET_DL_DST)          -> set_field;
action_type(?OFPAT_SET_NW_SRC)          -> set_field;
action_type(?OFPAT_SET_NW_DST)          -> set_field;
action_type(?OFPAT_SET_NW_TOS)          -> set_field;
action_type(?OFPAT_SET_NW_ECN)          -> set_field;
action_type(?OFPAT_SET_TP_SRC)          -> set_field;
action_type(?OFPAT_SET_TP_DST)          -> set_field;
action_type(copy_ttl_out)               -> ?OFPAT_COPY_TTL_OUT;
action_type(?OFPAT_COPY_TTL_OUT)        -> copy_ttl_out;
action_type(copy_ttl_in)                -> ?OFPAT_COPY_TTL_IN;
action_type(?OFPAT_COPY_TTL_IN)         -> copy_ttl_in;
action_type(?OFPAT_SET_MPLS_LABEL)      -> set_field;
action_type(?OFPAT_SET_MPLS_TC)         -> set_field;
action_type(set_mpls_ttl)               -> ?OFPAT_SET_MPLS_TTL;
action_type(?OFPAT_SET_MPLS_TTL)        -> set_mpls_ttl;
action_type(dec_mpls_ttl)               -> ?OFPAT_DEC_MPLS_TTL;
action_type(?OFPAT_DEC_MPLS_TTL)        -> dec_mpls_ttl;
action_type(push_vlan)                  -> ?OFPAT_PUSH_VLAN;
action_type(?OFPAT_PUSH_VLAN)           -> push_vlan;
action_type(pop_vlan)                   -> ?OFPAT_POP_VLAN;
action_type(?OFPAT_POP_VLAN)            -> pop_vlan;
action_type(push_mpls)                  -> ?OFPAT_PUSH_MPLS;
action_type(?OFPAT_PUSH_MPLS)           -> push_mpls;
action_type(pop_mpls)                   -> ?OFPAT_POP_MPLS;
action_type(?OFPAT_POP_MPLS)            -> pop_mpls;
action_type(set_queue)                  -> ?OFPAT_SET_QUEUE;
action_type(?OFPAT_SET_QUEUE)           -> set_queue;
action_type(group)                      -> ?OFPAT_GROUP;
action_type(?OFPAT_GROUP)               -> group;
action_type(set_nw_ttl)                 -> ?OFPAT_SET_NW_TTL;
action_type(?OFPAT_SET_NW_TTL)          -> set_nw_ttl;
action_type(dec_nw_ttl)                 -> ?OFPAT_DEC_NW_TTL;
action_type(?OFPAT_DEC_NW_TTL)          -> dec_nw_ttl;
action_type(experimenter)               -> ?OFPAT_EXPERIMENTER;
action_type(?OFPAT_EXPERIMENTER)        -> experimenter;
action_type(?OFPAT_EXPERIMENTER_BIT)    -> experimenter;
action_type(Type) when is_atom(Type)    -> throw({bad_type, Type});
action_type(Type) when is_integer(Type) -> throw({bad_value, Type}).

action_set_type(vlan_vid) -> ?OFPAT_SET_VLAN_VID;
action_set_type(?OFPAT_SET_VLAN_VID) -> vlan_vid;
action_set_type(vlan_pcp) -> ?OFPAT_SET_VLAN_PCP;
action_set_type(?OFPAT_SET_VLAN_PCP) -> vlan_pcp;
action_set_type(eth_src) -> ?OFPAT_SET_DL_SRC;
action_set_type(?OFPAT_SET_DL_SRC) -> eth_src;
action_set_type(eth_dst) -> ?OFPAT_SET_DL_DST;
action_set_type(?OFPAT_SET_DL_DST) -> eth_dst;
action_set_type(ipv4_src) -> ?OFPAT_SET_NW_SRC;
action_set_type(?OFPAT_SET_NW_SRC) -> ipv4_src;
action_set_type(ipv4_dst) -> ?OFPAT_SET_NW_DST;
action_set_type(?OFPAT_SET_NW_DST) -> ipv4_dst;
action_set_type(ip_dscp) -> ?OFPAT_SET_NW_TOS;
action_set_type(?OFPAT_SET_NW_TOS) -> ip_dscp;
action_set_type(ip_ecn) -> ?OFPAT_SET_NW_ECN;
action_set_type(?OFPAT_SET_NW_ECN) -> ip_ecn;
action_set_type(tcp_src) -> ?OFPAT_SET_TP_SRC;
action_set_type(tcp_dst) -> ?OFPAT_SET_TP_DST;
action_set_type(udp_src) -> ?OFPAT_SET_TP_SRC;
action_set_type(udp_dst) -> ?OFPAT_SET_TP_DST;
action_set_type(sctp_src) -> ?OFPAT_SET_TP_SRC;
action_set_type(sctp_dst) -> ?OFPAT_SET_TP_DST;
action_set_type(mpls_label) -> ?OFPAT_SET_MPLS_LABEL;
action_set_type(?OFPAT_SET_MPLS_LABEL) -> mpls_label;
action_set_type(mpls_tc) -> ?OFPAT_SET_MPLS_TC;
action_set_type(?OFPAT_SET_MPLS_TC) -> mpls_tc;
action_set_type(?OFPAT_SET_TP_SRC) -> tp_src;
action_set_type(?OFPAT_SET_TP_DST) -> tp_dst;
action_set_type(Type) when is_integer(Type) -> throw({bad_value, Type}).

%%%-----------------------------------------------------------------------------
%%% Controller-to-Switch Messages
%%%-----------------------------------------------------------------------------

%%% Features (Handshake) -------------------------------------------------------

capability(flow_stats)                 -> ?OFPC_FLOW_STATS;
capability(?OFPC_FLOW_STATS)           -> flow_stats;
capability(table_stats)                -> ?OFPC_TABLE_STATS;
capability(?OFPC_TABLE_STATS)          -> table_stats;
capability(port_stats)                 -> ?OFPC_PORT_STATS;
capability(?OFPC_PORT_STATS)           -> port_stats;
capability(group_stats)                -> ?OFPC_GROUP_STATS;
capability(?OFPC_GROUP_STATS)          -> group_stats;
capability(ip_reasm)                   -> ?OFPC_IP_REASM;
capability(?OFPC_IP_REASM)             -> ip_reasm;
capability(queue_stats)                -> ?OFPC_QUEUE_STATS;
capability(?OFPC_QUEUE_STATS)          -> queue_stats;
capability(arp_match_ip)               -> ?OFPC_ARP_MATCH_IP;
capability(?OFPC_ARP_MATCH_IP)         -> arp_match_ip;
capability(Type) when is_atom(Type)    -> throw({bad_type, Type});
capability(Type) when is_integer(Type) -> throw({bad_value, Type}).

%%% Switch Configuration -------------------------------------------------------

configuration(frag_drop)                       -> ?OFPC_FRAG_DROP;
configuration(?OFPC_FRAG_DROP)                 -> frag_drop;
configuration(frag_reasm)                      -> ?OFPC_FRAG_REASM;
configuration(?OFPC_FRAG_REASM)                -> frag_reasm;
configuration(invalid_ttl_to_controller)       -> ?OFPC_INVALID_TTL_TO_CONTROLLER;
configuration(?OFPC_INVALID_TTL_TO_CONTROLLER) -> invalid_ttl_to_controller;
configuration(Type) when is_atom(Type)         -> throw({bad_type, Type});
configuration(Type) when is_integer(Type)      -> throw({bad_value, Type}).

%%% Modify-State ---------------------------------------------------------------

flow_command(add)                        -> ?OFPFC_ADD;
flow_command(?OFPFC_ADD)                 -> add;
flow_command(modify)                     -> ?OFPFC_MODIFY;
flow_command(?OFPFC_MODIFY)              -> modify;
flow_command(modify_strict)              -> ?OFPFC_MODIFY_STRICT;
flow_command(?OFPFC_MODIFY_STRICT)       -> modify_strict;
flow_command(delete)                     -> ?OFPFC_DELETE;
flow_command(?OFPFC_DELETE)              -> delete;
flow_command(delete_strict)              -> ?OFPFC_DELETE_STRICT;
flow_command(?OFPFC_DELETE_STRICT)       -> delete_strict;
flow_command(Type) when is_atom(Type)    -> throw({bad_type, Type});
flow_command(Type) when is_integer(Type) -> throw({bad_value, Type}).

flow_flag(send_flow_rem)              -> ?OFPFF_SEND_FLOW_REM;
flow_flag(?OFPFF_SEND_FLOW_REM)       -> send_flow_rem;
flow_flag(check_overlap)              -> ?OFPFF_CHECK_OVERLAP;
flow_flag(?OFPFF_CHECK_OVERLAP)       -> check_overlap;
flow_flag(Type) when is_atom(Type)    -> throw({bad_type, Type});
flow_flag(Type) when is_integer(Type) -> throw({bad_value, Type}).

encode_buffer_id(no_buffer)                -> ?OFPCML_NO_BUFFER;
encode_buffer_id(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_buffer_id(Int) when is_integer(Int) -> Int.

decode_buffer_id(?OFPCML_NO_BUFFER)        -> no_buffer;
decode_buffer_id(Int) when is_integer(Int) -> Int.

%%% Rest -----------------------------------------------------------------------

encode_table_id(all)                      -> ?OFPTT_ALL;
encode_table_id(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_table_id(Int) when is_integer(Int) -> Int.

decode_table_id(?OFPTT_ALL)               -> all;
decode_table_id(Int) when is_integer(Int) -> Int.

encode_group_id(any)                      -> ?OFPG_ANY;
encode_group_id(all)                      -> ?OFPG_ALL;
encode_group_id(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_group_id(Int) when is_integer(Int) -> Int.

decode_group_id(?OFPG_ANY)                -> any;
decode_group_id(?OFPG_ALL)                -> all;
decode_group_id(Int) when is_integer(Int) -> Int.

%%%-----------------------------------------------------------------------------
%%% Helper functions
%%%-----------------------------------------------------------------------------

-spec get_experimenter_bit(atom()) -> integer().
get_experimenter_bit(instruction_type) ->
    ?OFPIT_EXPERIMENTER_BIT;
get_experimenter_bit(action_type) ->
    ?OFPAT_EXPERIMENTER_BIT.
