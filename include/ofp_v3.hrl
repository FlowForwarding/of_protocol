%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc OpenFlow Protocol version 1.2 specific header.
%%% @end
%%%-----------------------------------------------------------------------------

%% Protocol version
-define(VERSION, 3).

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
-define(OFPT_ROLE_REQUEST, 24).
-define(OFPT_ROLE_REPLY, 25).

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

%% Queue types; enum ofp_queue_properties
-define(OFPQT_MIN_RATE, 1).
-define(OFPQT_MAX_RATE, 2).
-define(OFPQT_EXPERIMENTER, 16#ffff).

%%% Flow Match Structures ------------------------------------------------------

%% Match types; enum ofp_match_type
-define(OFPMT_STANDARD, 0).
-define(OFPMT_OXM, 1).

%% OXM Field classes; enum ofp_oxm_class
-define(OFPXMC_NXM_0, 0).
-define(OFPXMC_NXM_1, 1).
-define(OFPXMC_OPENFLOW_BASIC, 16#8000).
-define(OFPXMC_EXPERIMENTER, 16#ffff).

%% OXM OpenFlow Basic field types; enum oxm_ofb_match_fields
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

%% VLAN ids; enum ofp_vlan_id
-define(OFPVID_PRESENT, 16#1000).
-define(OFPVID_NONE, 16#0000).

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
-define(OFPAT_EXPERIMENTER_BIT, 31).

%%%-----------------------------------------------------------------------------
%%% Controller-to-Switch Messages
%%%-----------------------------------------------------------------------------

%%% Features (Handshake) -------------------------------------------------------

%% Capabilities of the switch; enum ofp_capabilities
-define(OFPC_FLOW_STATS, 0).
-define(OFPC_TABLE_STATS, 1).
-define(OFPC_PORT_STATS, 2).
-define(OFPC_GROUP_STATS, 3).
-define(OFPC_IP_REASM, 5).
-define(OFPC_QUEUE_STATS, 6).
-define(OFPC_PORT_BLOCKED, 8).

%%% Switch Configuration -------------------------------------------------------

%% Configuration flags; enum ofp_config_flags
-define(OFPC_FRAG_DROP, 0).
-define(OFPC_FRAG_REASM, 1).
-define(OFPC_INVALID_TTL_TO_CONTROLLER, 2).

%%% Modify-State ---------------------------------------------------------------

%% Flow mod commands
-define(OFPFC_ADD, 0).
-define(OFPFC_MODIFY, 1).
-define(OFPFC_MODIFY_STRICT, 2).
-define(OFPFC_DELETE, 3).
-define(OFPFC_DELETE_STRICT, 4).

%% Flow mod flags
-define(OFPFF_SEND_FLOW_REM, 0).
-define(OFPFF_CHECK_OVERLAP, 1).
-define(OFPFF_RESET_COUNTS, 2).

%%% Rest -----------------------------------------------------------------------

%% Table ids
-define(OFPTT_MAX, 16#fe).
-define(OFPTT_ALL, 16#ff).

%% Table config
-define(OFPTC_TABLE_MISS_CONTINUE, 0).
-define(OFPTC_TABLE_MISS_DROP, 1).
-define(OFPTC_TABLE_MISS_MASK, 3).

%% Group mod commands
-define(OFPGC_ADD, 0).
-define(OFPGC_MODIFY, 1).
-define(OFPGC_DELETE, 2).

%% Group types
-define(OFPGT_ALL, 0).
-define(OFPGT_SELECT, 1).
-define(OFPGT_INDIRECT, 2).
-define(OFPGT_FF, 3).

%% Group ids
-define(OFPG_MAX, 16#fffffffd).
-define(OFPG_ANY, 16#fffffffe).
-define(OFPG_ALL, 16#ffffffff).

%% Stats types
-define(OFPST_DESC, 0).
-define(OFPST_FLOW, 1).
-define(OFPST_AGGREGATE, 2).
-define(OFPST_TABLE, 3).
-define(OFPST_PORT, 4).
-define(OFPST_QUEUE, 5).
-define(OFPST_GROUP, 6).
-define(OFPST_GROUP_DESC, 7).
-define(OFPST_GROUP_FEATURES, 8).
-define(OFPST_EXPERIMENTER, 16#ffff).

%% Stats request flags - none yet defined
%% -define(OFPSF_REQ_*)

%% Stats reply flags
-define(OFPSF_REPLY_MORE, 1).

%% Group feature capabilities
-define(OFPGFC_SELECT_WEIGHT, 0).
-define(OFPGFC_SELECT_LIVENESS, 1).
-define(OFPGFC_CHAINING, 2).
-define(OFPGFC_CHAINING_CHECKS, 3).

%% Controller roles
-define(OFPCR_ROLE_NOCHANGE, 0).
-define(OFPCR_ROLE_EQUAL, 1).
-define(OFPCR_ROLE_MASTER, 2).
-define(OFPCR_ROLE_SLAVE, 3).

%% Packet-in reasons
-define(OFPR_NO_MATCH, 0).
-define(OFPR_ACTION, 1).
-define(OFPR_INVALID_TTL, 2).

%% Flow removed reasons
-define(OFPRR_IDLE_TIMEOUT, 0).
-define(OFPRR_HARD_TIMEOUT, 1).
-define(OFPRR_DELETE, 2).
-define(OFPRR_GROUP_DELETE, 3).

%% Port status reasons
-define(OFPPR_ADD, 0).
-define(OFPPR_DELETE, 1).
-define(OFPPR_MODIFY, 2).

%% Error types
-define(OFPET_HELLO_FAILED, 0).
-define(OFPET_BAD_REQUEST, 1).
-define(OFPET_BAD_ACTION, 2).
-define(OFPET_BAD_INSTRUCTION, 3).
-define(OFPET_BAD_MATCH, 4).
-define(OFPET_FLOW_MOD_FAILED, 5).
-define(OFPET_GROUP_MOD_FAILED, 6).
-define(OFPET_PORT_MOD_FAILED, 7).
-define(OFPET_TABLE_MOD_FAILED, 8).
-define(OFPET_QUEUE_OP_FAILED, 9).
-define(OFPET_SWITCH_CONFIG_FAILED, 10).
-define(OFPET_ROLE_REQUEST_FAILED, 11).
-define(OFPET_EXPERIMENTER, 16#ffff).

%% Hello Failed error codes
-define(OFPHFC_INCOMPATIBLE, 0).
-define(OFPHFC_EPERM, 1).

%% Bad Request error codes
-define(OFPBRC_BAD_VERSION, 0).
-define(OFPBRC_BAD_TYPE, 1).
-define(OFPBRC_BAD_STAT, 2).
-define(OFPBRC_BAD_EXPERIMENTER, 3).
-define(OFPBRC_BAD_EXP_TYPE, 4).
-define(OFPBRC_EPERM, 5).
-define(OFPBRC_BAD_LEN, 6).
-define(OFPBRC_BUFFER_EMPTY, 7).
-define(OFPBRC_BUFFER_UNKNOWN, 8).
-define(OFPBRC_BAD_TABLE_ID, 9).
-define(OFPBRC_IS_SLAVE, 10).
-define(OFPBRC_BAD_PORT, 11).
-define(OFPBRC_BAD_PACKET, 12).

%% Bad Action error codes
-define(OFPBAC_BAD_TYPE, 0).
-define(OFPBAC_BAD_LEN, 1).
-define(OFPBAC_BAD_EXPERIMENTER, 2).
-define(OFPBAC_BAD_EXP_TYPE, 3).
-define(OFPBAC_BAD_OUT_PORT, 4).
-define(OFPBAC_BAD_ARGUMENT, 5).
-define(OFPBAC_EPERM, 6).
-define(OFPBAC_TOO_MANY, 7).
-define(OFPBAC_BAD_QUEUE, 8).
-define(OFPBAC_BAD_OUT_GROUP, 9).
-define(OFPBAC_MATCH_INCONSISTENT, 10).
-define(OFPBAC_UNSUPPORTED_ORDER, 11).
-define(OFPBAC_BAD_TAG, 12).
-define(OFPBAC_BAD_SET_TYPE, 13).
-define(OFPBAC_BAD_SET_LEN, 14).
-define(OFPBAC_BAD_SET_ARGUMENT, 15).

%% Bad Instruction error codes
-define(OFPBIC_UNKNOWN_INST, 0).
-define(OFPBIC_UNSUP_INST, 1).
-define(OFPBIC_BAD_TABLE_ID, 2).
-define(OFPBIC_UNSUP_METADATA, 3).
-define(OFPBIC_UNSUP_METADATA_MASK, 4).
-define(OFPBIC_BAD_EXPERIMENTER, 5).
-define(OFPBIC_BAD_EXP_TYPE, 6).
-define(OFPBIC_BAD_LEN, 7).
-define(OFPBIC_EPERM, 8).

%% Bad Match error codes
-define(OFPBMC_BAD_TYPE, 0).
-define(OFPBMC_BAD_LEN, 1).
-define(OFPBMC_BAD_TAG, 2).
-define(OFPBMC_BAD_DL_ADDR_MASK, 3).
-define(OFPBMC_BAD_NW_ADDR_MASK, 4).
-define(OFPBMC_BAD_WILDCARDS, 5).
-define(OFPBMC_BAD_FIELD, 6).
-define(OFPBMC_BAD_VALUE, 7).
-define(OFPBMC_BAD_MASK, 8).
-define(OFPBMC_BAD_PREREQ, 9).
-define(OFPBMC_DUP_FIELD, 10).
-define(OFPBMC_EPERM, 11).

%% Flow Mod Failed error codes
-define(OFPFMFC_UNKNOWN, 0).
-define(OFPFMFC_TABLE_FULL, 1).
-define(OFPFMFC_BAD_TABLE_ID, 2).
-define(OFPFMFC_OVERLAP, 3).
-define(OFPFMFC_EPERM, 4).
-define(OFPFMFC_BAD_TIMEOUT, 5).
-define(OFPFMFC_BAD_COMMAND, 6).
-define(OFPFMFC_BAD_FLAGS, 7).

%% Group Mod Failed error codes
-define(OFPGMFC_GROUP_EXISTS, 0).
-define(OFPGMFC_INVALID_GROUP, 1).
-define(OFPGMFC_WEIGHT_UNSUPPORTED, 2).
-define(OFPGMFC_OUT_OF_GROUPS, 3).
-define(OFPGMFC_OUT_OF_BUCKETS, 4).
-define(OFPGMFC_CHAINING_UNSUPPORTED, 5).
-define(OFPGMFC_WATCH_UNSUPPORTED, 6).
-define(OFPGMFC_LOOP, 7).
-define(OFPGMFC_UNKNOWN_GROUP, 8).
-define(OFPGMFC_CHAINED_GROUP, 9).
-define(OFPGMFC_BAD_TYPE, 10).
-define(OFPGMFC_BAD_COMMAND, 11).
-define(OFPGMFC_BAD_BUCKET, 12).
-define(OFPGMFC_BAD_WATCH, 13).
-define(OFPGMFC_EPERM, 14).

%% Port Mod Failed error codes
-define(OFPPMFC_BAD_PORT, 0).
-define(OFPPMFC_BAD_HW_ADDR, 1).
-define(OFPPMFC_BAD_CONFIG, 2).
-define(OFPPMFC_BAD_ADVERTISE, 3).
-define(OFPPMFC_EPERM, 4).

%% Table Mod Failed error codes
-define(OFPTMFC_BAD_TABLE, 0).
-define(OFPTMFC_BAD_CONFIG, 1).
-define(OFPTMFC_EPERM, 2).

%% Queue Op Failed error codes
-define(OFPQOFC_BAD_PORT, 0).
-define(OFPQOFC_BAD_QUEUE, 1).
-define(OFPQOFC_EPERM, 2).

%% Switch Config Failed error codes
-define(OFPSCFC_BAD_FLAGS, 0).
-define(OFPSCFC_BAD_LEN, 1).
-define(OFPSCFC_EPERM, 2).

%% Role Request Failed error codes
-define(OFPRRFC_STALE, 0).
-define(OFPRRFC_UNSUP, 1).
-define(OFPRRFC_BAD_ROLE, 2).

%% Controller max length; Buffer ids
-define(OFPCML_MAX, 16#ffe5).
-define(OFPCML_NO_BUFFER, 16#ffff).

%%%-----------------------------------------------------------------------------
%%% Sizes
%%%-----------------------------------------------------------------------------

%% Message sizes
-define(FEATURES_REQUEST_SIZE, 8).
-define(FEATURES_REPLY_SIZE, 32).
-define(GET_CONFIG_REQUEST_SIZE, 8).
-define(GET_CONFIG_REPLY_SIZE, 12).
-define(SET_CONFIG_SIZE, 12).
-define(TABLE_MOD_SIZE, 16).
-define(FLOW_MOD_SIZE, 56).
-define(GROUP_MOD_SIZE, 16).
-define(PORT_MOD_SIZE, 40).
-define(DESC_STATS_REQUEST_SIZE, 16).
-define(DESC_STATS_REPLY_SIZE, 1072).
-define(FLOW_STATS_REQUEST_SIZE, 56).
-define(FLOW_STATS_REPLY_SIZE, 16).
-define(AGGREGATE_STATS_REQUEST_SIZE, 56).
-define(AGGREGATE_STATS_REPLY_SIZE, 40).
-define(TABLE_STATS_REQUEST_SIZE, 16).
-define(TABLE_STATS_REPLY_SIZE, 16).
-define(PORT_STATS_REQUEST_SIZE, 24).
-define(PORT_STATS_REPLY_SIZE, 16).
-define(QUEUE_STATS_REQUEST_SIZE, 24).
-define(QUEUE_STATS_REPLY_SIZE, 16).
-define(GROUP_STATS_REQUEST_SIZE, 24).
-define(GROUP_STATS_REPLY_SIZE, 16).
-define(GROUP_DESC_STATS_REQUEST_SIZE, 16).
-define(GROUP_DESC_STATS_REPLY_SIZE, 16).
-define(GROUP_FEATURES_STATS_REQUEST_SIZE, 16).
-define(GROUP_FEATURES_STATS_REPLY_SIZE, 56).
-define(EXPERIMENTER_STATS_REQUEST_SIZE, 24).
-define(EXPERIMENTER_STATS_REPLY_SIZE, 24).
-define(QUEUE_GET_CONFIG_REQUEST_SIZE, 16).
-define(QUEUE_GET_CONFIG_REPLY_SIZE, 16).
-define(PACKET_OUT_SIZE, 24).
-define(BARRIER_REQUEST_SIZE, 8).
-define(BARRIER_REPLY_SIZE, 8).
-define(ROLE_REQUEST_SIZE, 24).
-define(ROLE_REPLY_SIZE, 24).
-define(PACKET_IN_SIZE, 24).
-define(FLOW_REMOVED_SIZE, 56).
-define(PORT_STATUS_SIZE, 80).
-define(ERROR_SIZE, 12).
-define(ERROR_EXPERIMENTER_SIZE, 16).
-define(HELLO_SIZE, 8).
-define(ECHO_REQUEST_SIZE, 8).
-define(ECHO_REPLY_SIZE, 8).
-define(EXPERIMENTER_SIZE, 16).

%% Structure sizes
-define(PORT_SIZE, 64).
-define(PACKET_QUEUE_SIZE, 16).
-define(QUEUE_PROP_MIN_RATE_SIZE, 16).
-define(QUEUE_PROP_MAX_RATE_SIZE, 16).
-define(QUEUE_PROP_EXPERIMENTER_SIZE, 16).
-define(OXM_FIELD_SIZE, 4).
-define(MATCH_SIZE, 8).
-define(INSTRUCTION_GOTO_TABLE_SIZE, 8).
-define(INSTRUCTION_WRITE_METADATA_SIZE, 24).
-define(INSTRUCTION_WRITE_ACTIONS_SIZE, 8).
-define(INSTRUCTION_APPLY_ACTIONS_SIZE, 8).
-define(INSTRUCTION_CLEAR_ACTIONS_SIZE, 8).
-define(INSTRUCTION_EXPERIMENTER_SIZE, 8).
-define(ACTION_COPY_TTL_IN_SIZE, 8).
-define(ACTION_POP_MPLS_SIZE, 8).
-define(ACTION_POP_VLAN_SIZE, 8).
-define(ACTION_PUSH_MPLS_SIZE, 8).
-define(ACTION_PUSH_VLAN_SIZE, 8).
-define(ACTION_COPY_TTL_OUT_SIZE, 8).
-define(ACTION_DEC_MPLS_TTL_SIZE, 8).
-define(ACTION_DEC_NW_TTL_SIZE, 8).
-define(ACTION_SET_MPLS_TTL_SIZE, 8).
-define(ACTION_SET_NW_TTL_SIZE, 8).
-define(ACTION_SET_FIELD_SIZE, 8).
-define(ACTION_SET_QUEUE_SIZE, 8).
-define(ACTION_GROUP_SIZE, 8).
-define(ACTION_OUTPUT_SIZE, 16).
-define(ACTION_EXPERIMENTER_SIZE, 8).
-define(BUCKET_SIZE, 16).
-define(BUCKET_COUNTER_SIZE, 16).
-define(FLOW_STATS_SIZE, 56).
-define(TABLE_STATS_SIZE, 128).
-define(PORT_STATS_SIZE, 104).
-define(QUEUE_STATS_SIZE, 32).
-define(GROUP_STATS_SIZE, 32).
-define(GROUP_DESC_STATS_SIZE, 8).

%% OXM field sizes (in bits)
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
