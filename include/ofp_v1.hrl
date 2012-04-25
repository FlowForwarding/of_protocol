%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc OpenFlow Protocol version 1.0 specific header.
%%% @end
%%%-----------------------------------------------------------------------------

%% Protocol version
-define(VERSION, 1).

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
-define(OFPT_PORT_MOD, 15).
-define(OFPT_STATS_REQUEST, 16).
-define(OFPT_STATS_REPLY, 17).
-define(OFPT_BARRIER_REQUEST, 18).
-define(OFPT_BARRIER_REPLY, 19).
-define(OFPT_QUEUE_GET_CONFIG_REQUEST, 20).
-define(OFPT_QUEUE_GET_CONFIG_REPLY, 21).

%%% Port Structures ------------------------------------------------------------

%% Port config; enum ofp_port_config
-define(OFPPC_PORT_DOWN, 0).
-define(OFPPC_NO_STP, 1).
-define(OFPPC_NO_RECV, 2).
-define(OFPPC_NO_RECV_STP, 3).
-define(OFPPC_NO_FLOOD, 4).
-define(OFPPC_NO_FWD, 5).
-define(OFPPC_NO_PACKET_IN, 6).

%% Port state; enum ofp_port_state
-define(OFPPS_LINK_DOWN, 0).

%% Port numbers; Reserved ports; enum ofp_port_no
-define(OFPP_MAX, 16#ff00).
-define(OFPP_IN_PORT, 16#fff8).
-define(OFPP_TABLE, 16#fff9).
-define(OFPP_NORMAL, 16#fffa).
-define(OFPP_FLOOD, 16#fffb).
-define(OFPP_ALL, 16#fffc).
-define(OFPP_CONTROLLER, 16#fffd).
-define(OFPP_LOCAL, 16#fffe).
-define(OFPP_ANY, 16#ffff).

%% Port features; enum ofp_port_features
-define(OFPPF_10MB_HD, 0).
-define(OFPPF_10MB_FD, 1).
-define(OFPPF_100MB_HD, 2).
-define(OFPPF_100MB_FD, 3).
-define(OFPPF_1GB_HD, 4).
-define(OFPPF_1GB_FD, 5).
-define(OFPPF_10GB_FD, 6).
-define(OFPPF_OTHER, 7).
-define(OFPPF_COPPER, 8).
-define(OFPPF_FIBER, 9).
-define(OFPPF_AUTONEG, 10).
-define(OFPPF_PAUSE, 11).
-define(OFPPF_PAUSE_ASYM, 12).

%%% Queue Structures -----------------------------------------------------------

%% Queue ids
-define(OFPQ_MAX, 16#fffffffe).
-define(OFPQ_ALL, 16#ffffffff).

%% Queue properties; enum ofp_queue_properties
-define(OFPQT_MIN_RATE, 1).

%%% Flow Match Structures ------------------------------------------------------

%% Flow wildcards; enum ofp_flow_wildcards
-define(OFPFW_IN_PORT, 0).
-define(OFPFW_DL_VLAN, 1).
-define(OFPFW_DL_SRC, 2).
-define(OFPFW_DL_DST, 3).
-define(OFPFW_DL_TYPE, 4).
-define(OFPFW_NW_PROTO, 5).
-define(OFPFW_TP_SRC, 6).      %% TCP/UDP
-define(OFPFW_TP_DST, 7).      %% TCP/UDP
%% Masks for IP src and dst.
-define(OFPFW_DL_VLAN_PCP, 20).
-define(OFPFW_NW_TOS, 21).
-define(OFPFW_ALL, 4194303).

%%% Action Structures ----------------------------------------------------------

%% Action types; enum ofp_action_type
-define(OFPAT_OUTPUT, 0).
-define(OFPAT_SET_VLAN_VID, 1).
-define(OFPAT_SET_VLAN_PCP, 2).
-define(OFPAT_STRIP_VLAN, 3).
-define(OFPAT_SET_DL_SRC, 4).
-define(OFPAT_SET_DL_DST, 5).
-define(OFPAT_SET_NW_SRC, 6).
-define(OFPAT_SET_NW_DST, 7).
-define(OFPAT_SET_NW_TOS, 8).
-define(OFPAT_SET_TP_SRC, 9).
-define(OFPAT_SET_TP_DST, 10).
-define(OFPAT_ENQUEUE, 11).
-define(OFPAT_VENDOR, 16#ffff).
-define(OFPAT_VENDOR_BIT, 31).

%%%-----------------------------------------------------------------------------
%%% Controller-to-Switch Messages
%%%-----------------------------------------------------------------------------

%%% Features (Handshake) -------------------------------------------------------

%% Capabilities of the switch; enum ofp_capabilities
-define(OFPC_FLOW_STATS, 0).
-define(OFPC_TABLE_STATS, 1).
-define(OFPC_PORT_STATS, 2).
-define(OFPC_STP, 3).
-define(OFPC_IP_REASM, 5).
-define(OFPC_QUEUE_STATS, 6).
-define(OFPC_ARP_MATCH_IP, 7).

%%% Switch Configuration -------------------------------------------------------

%% Configuration flags; enum ofp_config_flags
-define(OFPC_FRAG_DROP, 0).
-define(OFPC_FRAG_REASM, 1).

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
-define(OFPFF_EMERG, 2).

%%% Read-State -----------------------------------------------------------------

%% Stats types
-define(OFPST_DESC, 0).
-define(OFPST_FLOW, 1).
-define(OFPST_TABLE, 3).

%% Stats request flags - none yet defined
%% -define(OFPSF_REQ_*)

%% Stats reply flags
-define(OFPSF_REPLY_MORE, 1).

%%% Rest -----------------------------------------------------------------------

%% Controller max length; Buffer ids
-define(OFPCML_NO_BUFFER, 16#ffff).

%% Table ids
-define(OFPTT_MAX, 16#fe).
-define(OFPTT_ALL, 16#ff).

%%%-----------------------------------------------------------------------------
%%% Switch-to-Controller Messages
%%%-----------------------------------------------------------------------------

%%% Packet-In ------------------------------------------------------------------

-define(OFPR_NO_MATCH, 0).
-define(OFPR_ACTION, 1).

%%%-----------------------------------------------------------------------------
%%% Sizes
%%%-----------------------------------------------------------------------------

%% Message sizes
-define(HELLO_SIZE, 8).
-define(FEATURES_REQUEST_SIZE, 8).
-define(FEATURES_REPLY_SIZE, 32).
-define(GET_CONFIG_REQUEST_SIZE, 8).
-define(GET_CONFIG_REPLY_SIZE, 12).
-define(SET_CONFIG_SIZE, 12).
-define(FLOW_MOD_SIZE, 72).
-define(DESC_STATS_REQUEST_SIZE, 12).
-define(DESC_STATS_REPLY_SIZE, 1068).
-define(FLOW_STATS_REQUEST_SIZE, 56).
-define(FLOW_STATS_REPLY_SIZE, 12).
-define(TABLE_STATS_REQUEST_SIZE, 12).
-define(TABLE_STATS_REPLY_SIZE, 12).

%% Structure sizes
-define(PORT_SIZE, 48).
-define(PACKET_QUEUE_SIZE, 8).
-define(QUEUE_PROP_MIN_RATE_SIZE, 16).
-define(MATCH_SIZE, 40).
-define(ACTION_POP_VLAN_SIZE, 8).
-define(ACTION_SET_VLAN_VID_SIZE, 8).
-define(ACTION_SET_VLAN_PCP_SIZE, 8).
-define(ACTION_SET_ETH_SIZE, 16).
-define(ACTION_SET_IPV4_SIZE, 8).
-define(ACTION_SET_IP_DSCP_SIZE, 8).
-define(ACTION_SET_TP_SIZE, 8).
-define(ACTION_SET_QUEUE_SIZE, 8).
-define(ACTION_OUTPUT_SIZE, 8).
-define(ACTION_EXPERIMENTER_SIZE, 8).
-define(FLOW_STATS_SIZE, 88).
-define(TABLE_STATS_SIZE, 64).
