%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc OpenFlow Protocol version 1.1 specific header.
%%% @end
%%%-----------------------------------------------------------------------------

%% Protocol version
-define(VERSION, 2).

%% Misc
-define(OFP_ETH_ALEN, 6).
-define(OFP_MAX_PORT_NAME_LEN, 16).
-define(OFP_MAX_TABLE_NAME_LEN, 32).
-define(DESC_STR_LEN, 256).
-define(SERIAL_NUM_LEN, 32).

%%%-----------------------------------------------------------------------------
%%% Common Structure
%%%-----------------------------------------------------------------------------

%%% Header ---------------------------------------------------------------------

%% Message types; enum ofp_type
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

%%% Port Structures ------------------------------------------------------------

%% Port config; enum ofp_port_config
-define(OFPPC_PORT_DOWN, 0).
-define(OFPPC_NO_RECV, 2).
-define(OFPPC_NO_FWD, 5).
-define(OFPPC_NO_PACKET_IN, 6).

%% Port state; enum ofp_port_state
-define(OFPPS_LINK_DOWN, 0).
-define(OFPPS_BLOCKED, 1).
-define(OFPPS_LIVE, 2).

%% Port numbers; Reserved ports; enum ofp_port_no
-define(OFPP_MAX, 16#ffffff00).
-define(OFPP_IN_PORT, 16#fffffff8).
-define(OFPP_TABLE, 16#fffffff9).
-define(OFPP_NORMAL, 16#fffffffa).
-define(OFPP_FLOOD, 16#fffffffb).
-define(OFPP_ALL, 16#fffffffc).
-define(OFPP_CONTROLLER, 16#fffffffd).
-define(OFPP_LOCAL, 16#fffffffe).
-define(OFPP_ANY, 16#ffffffff).

%% Port features; enum ofp_port_features
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

%% Queue ids
-define(OFPQ_MAX, 16#fffffffe).
-define(OFPQ_ALL, 16#ffffffff).

%% Queue properties; enum ofp_queue_properties
-define(OFPQT_MIN_RATE, 1).

%%% Flow Match Structures ------------------------------------------------------

%% Match types; enum ofp_match_type
-define(OFPMT_STANDARD, 0).

%% Flow wildcards; enum ofp_flow_wildcards
-define(OFPFW_IN_PORT, 0).
-define(OFPFW_DL_VLAN, 1).
-define(OFPFW_DL_VLAN_PCP, 2).
-define(OFPFW_DL_TYPE, 3).
-define(OFPFW_NW_TOS, 4).
-define(OFPFW_NW_PROTO, 5).
-define(OFPFW_TP_SRC, 6).      %% TCP/UDP/SCTP
-define(OFPFW_TP_DST, 7).      %% TCP/UDP/SCTP
-define(OFPFW_MPLS_LABEL, 8).
-define(OFPFW_MPLS_TC, 9).
-define(OFPFW_ALL, 1023).

%% VLAN ids; enum ofp_vlan_id
-define(OFPVID_PRESENT, 16#fffe).
-define(OFPVID_NONE, 16#ffff).

%%% Flow Instruction Structures ------------------------------------------------

%% Instruction types; enum ofp_instruction_type
-define(OFPIT_GOTO_TABLE, 1).
-define(OFPIT_WRITE_METADATA, 2).
-define(OFPIT_WRITE_ACTIONS, 3).
-define(OFPIT_APPLY_ACTIONS, 4).
-define(OFPIT_CLEAR_ACTIONS, 5).
-define(OFPIT_EXPERIMENTER, 16#ffff).
-define(OFPIT_EXPERIMENTER_BIT, 31).

%%% Action Structures ----------------------------------------------------------

%% Action types; enum ofp_action_type
-define(OFPAT_OUTPUT, 0).
-define(OFPAT_SET_VLAN_VID, 1).
-define(OFPAT_SET_VLAN_PCP, 2).
-define(OFPAT_SET_DL_SRC, 3).
-define(OFPAT_SET_DL_DST, 4).
-define(OFPAT_SET_NW_SRC, 5).
-define(OFPAT_SET_NW_DST, 6).
-define(OFPAT_SET_NW_TOS, 7).
-define(OFPAT_SET_NW_ECN, 8).
-define(OFPAT_SET_TP_SRC, 9).
-define(OFPAT_SET_TP_DST, 10).
-define(OFPAT_COPY_TTL_OUT, 11).
-define(OFPAT_COPY_TTL_IN, 12).
-define(OFPAT_SET_MPLS_LABEL, 13).
-define(OFPAT_SET_MPLS_TC, 14).
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
-define(OFPAT_EXPERIMENTER, 16#ffff).
-define(OFPAT_EXPERIMENTER_BIT, 31).

%%% Rest -----------------------------------------------------------------------

%% Controller max length; Buffer ids
-define(OFPCML_MAX, 16#ffe5).
-define(OFPCML_NO_BUFFER, 16#ffff).

%%%-----------------------------------------------------------------------------
%%% Sizes
%%%-----------------------------------------------------------------------------

%% Structure sizes
-define(PORT_SIZE, 64).
-define(PACKET_QUEUE_SIZE, 8).
-define(QUEUE_PROP_MIN_RATE_SIZE, 16).
-define(MATCH_SIZE, 88).
-define(INSTRUCTION_GOTO_TABLE_SIZE, 8).
-define(INSTRUCTION_WRITE_METADATA_SIZE, 24).
-define(INSTRUCTION_WRITE_ACTIONS_SIZE, 8).
-define(INSTRUCTION_APPLY_ACTIONS_SIZE, 8).
-define(INSTRUCTION_CLEAR_ACTIONS_SIZE, 8).
-define(INSTRUCTION_EXPERIMENTER_SIZE, 8).
-define(ACTION_OUTPUT_SIZE, 16).
-define(ACTION_POP_MPLS_SIZE, 8).
-define(ACTION_POP_VLAN_SIZE, 8).
-define(ACTION_PUSH_MPLS_SIZE, 8).
-define(ACTION_PUSH_VLAN_SIZE, 8).
-define(ACTION_COPY_TTL_IN_SIZE, 8).
-define(ACTION_COPY_TTL_OUT_SIZE, 8).
-define(ACTION_DEC_MPLS_TTL_SIZE, 8).
-define(ACTION_DEC_NW_TTL_SIZE, 8).
-define(ACTION_SET_MPLS_TTL_SIZE, 8).
-define(ACTION_SET_NW_TTL_SIZE, 8).
-define(ACTION_SET_VLAN_VID_SIZE, 8).
-define(ACTION_SET_VLAN_PCP_SIZE, 8).
-define(ACTION_SET_MPLS_LABEL_SIZE, 8).
-define(ACTION_SET_MPLS_TC_SIZE, 8).
-define(ACTION_SET_ETH_SIZE, 16).
-define(ACTION_SET_IPV4_SIZE, 8).
-define(ACTION_SET_IP_DSCP_SIZE, 8).
-define(ACTION_SET_IP_ECN_SIZE, 8).
-define(ACTION_SET_TP_SIZE, 8).
-define(ACTION_SET_QUEUE_SIZE, 8).
-define(ACTION_GROUP_SIZE, 8).
-define(ACTION_EXPERIMENTER_SIZE, 8).
