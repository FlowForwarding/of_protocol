%%%-----------------------------------------------------------------------------
%%% Use is subject to License terms.
%%% @copyright (C) 2012 FlowForwarding.org
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

%%% Error codes ---------------------------------------------------------------

-define(OFPET_HELLO_FAILED, 0).
-define(OFPET_BAD_REQUEST, 1).
-define(OFPET_BAD_ACTION, 2).
-define(OFPET_FLOW_MOD_FAILED, 3).
-define(OFPET_PORT_MOD_FAILED, 4).
-define(OFPET_QUEUE_OP_FAILED, 5).

-define(OFPHFC_INCOMPATIBLE, 0).
-define(OFPHFC_EPERM, 1).

-define(OFPBRC_BAD_VERSION, 0).
-define(OFPBRC_BAD_TYPE, 1).
-define(OFPBRC_BAD_STAT, 2).
-define(OFPBRC_BAD_EXPERIMENTER, 3).
-define(OFPBRC_BAD_EXP_TYPE, 4).
-define(OFPBRC_EPERM, 5).
-define(OFPBRC_BAD_LEN, 6).
-define(OFPBRC_BUFFER_EMPTY, 7).
-define(OFPBRC_BUFFER_UNKNOWN, 8).

-define(OFPBAC_BAD_TYPE, 0).
-define(OFPBAC_BAD_LEN, 1).
-define(OFPBAC_BAD_EXPERIMENTER, 2).
-define(OFPBAC_BAD_EXP_TYPE, 3).
-define(OFPBAC_BAD_OUT_PORT, 4).
-define(OFPBAC_BAD_ARGUMENT, 5).
-define(OFPBAC_EPERM, 6).
-define(OFPBAC_TOO_MANY, 7).
-define(OFPBAC_BAD_QUEUE, 8).

-define(OFPFMFC_ALL_TABLES_FULL, 0).
-define(OFPFMFC_OVERLAP, 1).
-define(OFPFMFC_EPERM, 2).
-define(OFPFMFC_BAD_TIMEOUT, 3).
-define(OFPFMFC_BAD_COMMAND, 4).
-define(OFPFMFC_UNSUPPORTED, 5).

-define(OFPPMFC_BAD_PORT, 0).
-define(OFPPMFC_BAD_HW_ADDR, 1).

-define(OFPQOFC_BAD_PORT, 0).
-define(OFPQOFC_BAD_QUEUE, 1).
-define(OFPQOFC_EPERM, 2).

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
-define(OFPST_QUEUE, 5).

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

%%% Flow removed ----------------------------------------------------------------

-define(OFPRR_IDLE_TIMEOUT, 0).
-define(OFPRR_HARD_TIMEOUT, 1).
-define(OFPRR_DELETE, 2).

%%% Port status ------------------------------------------------------------------

-define(OFPPR_ADD, 0).
-define(OFPPR_DELETE, 1).
-define(OFPPR_MODIFY, 2).

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
-define(QUEUE_STATS_REQUEST_SIZE, 20).
-define(QUEUE_STATS_REPLY_SIZE, 12).

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
-define(QUEUE_STATS_SIZE, 32).

%%%-----------------------------------------------------------------------------
%%% Common Structures
%%%-----------------------------------------------------------------------------

%%% Port Structures ------------------------------------------------------------

-type ofp_port_config() :: port_down
                         | no_recv
                         | no_fwd
                         | no_packet_in
                         | no_stp       %% OFP 1.0
                         | no_recv_stp  %% OFP 1.0
                         | no_flood.    %% OFP 1.0

-type ofp_port_state() :: link_down
                        | blocked
                        | live.

-type ofp_port_reserved() :: all
                           | controller
                           | table
                           | in_port
                           | any        %% 'none' in OFP 1.0
                           | local
                           | normal
                           | flood.

-type ofp_port_no() :: integer()
                     | ofp_port_reserved().

-type ofp_port_feature() :: '10mb_hd'
                          | '10mb_fd'
                          | '100mb_hd'
                          | '100mb_fd'
                          | '1gb_hd'
                          | '1gb_fd'
                          | '10gb_fd'
                          | '40gb_fd'
                          | '100gb_fd'
                          | '1tb_fd'
                          | other
                          | copper
                          | fiber
                          | autoneg
                          | pause
                          | pause_asym.

%% Port
-record(ofp_port, {
          port_no :: ofp_port_no(),
          hw_addr :: binary(),
          name :: binary(),
          config = [] :: [ofp_port_config()],
          state = [] :: [ofp_port_state()],
          curr = [] :: [ofp_port_feature()],
          advertised = [] :: [ofp_port_feature()],
          supported = [] :: [ofp_port_feature()],
          peer = [] :: [ofp_port_feature()],
          curr_speed = 0 :: integer(),
          max_speed = 0 :: integer()
         }).
-type ofp_port() :: #ofp_port{}.

%%% Queue Structures -----------------------------------------------------------

%% Queue rates are given in permiles. Value > 1000 means QoS is disabled.

%% Min-Rate queue property
-record(ofp_queue_prop_min_rate, {
          rate :: integer()
         }).

%% Max-Rate queue property
-record(ofp_queue_prop_max_rate, {
          rate :: integer()
         }).

%% Experimenter queue property
-record(ofp_queue_prop_experimenter, {
          experimenter :: integer(),
          data = <<>> :: binary()
         }).

-type ofp_queue_property() :: #ofp_queue_prop_min_rate{} |
                              #ofp_queue_prop_max_rate{} |
                              #ofp_queue_prop_experimenter{}.

%% Packet queue
-record(ofp_packet_queue, {
          queue_id :: ofp_queue_id(),
          port_no :: ofp_port_no(),
          properties :: [ofp_queue_property()]
         }).
-type ofp_packet_queue() :: #ofp_packet_queue{}.

%%% Flow Match Structures ------------------------------------------------------

-type ofp_field_class() :: nxm_0
                         | nxm_1
                         | openflow_basic
                         | experimenter.

-type openflow_basic_type() :: in_port
                             | in_phy_port
                             | metadata
                             | eth_dst
                             | eth_src
                             | eth_type
                             | vlan_vid
                             | vlan_pcp
                             | ip_dscp
                             | ip_ecn
                             | ip_proto
                             | ipv4_src
                             | ipv4_dst
                             | tcp_src
                             | tcp_dst
                             | udp_src
                             | udp_dst
                             | sctp_src
                             | sctp_dst
                             | icmpv4_type
                             | icmpv4_code
                             | arp_op
                             | arp_spa
                             | arp_tpa
                             | arp_sha
                             | arp_tha
                             | ipv6_src
                             | ipv6_dst
                             | ipv6_label
                             | icmpv6_type
                             | icmpv6_code
                             | ipv6_nd_target
                             | ipv6_nd_sll
                             | ipv6_nd_tll
                             | mpls_label
                             | mpls_tc.

-type ofp_field_type() :: openflow_basic_type().

%% OXM field
-record(ofp_field, {
          class = openflow_basic :: ofp_field_class(),
          field :: ofp_field_type(),
          has_mask = false :: boolean(),
          value :: binary(),
          mask :: binary()
         }).
-type ofp_field() :: #ofp_field{}.

-type ofp_match_type() :: standard %% Deprecated
                        | oxm.

%% Match
-record(ofp_match, {
          type       = oxm :: ofp_match_type(),
          oxm_fields = []  :: [ofp_field()]
         }).

-type ofp_match() :: #ofp_match{}.

%%% Flow Instruction Structures ------------------------------------------------

%% Instruction structure for apply actions
-record(ofp_instruction_apply_actions, {
          seq = 1,
          actions :: [ofp_action()]
         }).

%% Instruction structure for clear actions
-record(ofp_instruction_clear_actions, {
          seq = 2
         }).

%% Instruction structure for write actions
-record(ofp_instruction_write_actions, {
          seq = 3,
          actions :: [ofp_action()]
         }).

%% Instruction structure for write metadata
-record(ofp_instruction_write_metadata, {
          seq = 4,
          metadata                 :: binary(),
          metadata_mask = <<1:64>> :: binary()
         }).

%% Instruction structure for goto table
-record(ofp_instruction_goto_table, {
          seq = 5,
          table_id :: integer()
         }).

%% Instruction structure for experimenter
-record(ofp_instruction_experimenter, {
          seq = 6,
          experimenter :: integer(),
          data = <<>> :: binary()
         }).

-type ofp_instruction() :: #ofp_instruction_goto_table{}
                         | #ofp_instruction_write_metadata{}
                         | #ofp_instruction_write_actions{}
                         | #ofp_instruction_apply_actions{}
                         | #ofp_instruction_clear_actions{}
                         | #ofp_instruction_experimenter{}.

%%% Action Structures ----------------------------------------------------------

%% Copy TTL inwards action
-record(ofp_action_copy_ttl_in, {
          seq = 1
         }).

%% Pop MPLS header action
-record(ofp_action_pop_mpls, {
          seq = 2,
          ethertype :: integer()
         }).

%% Pop VLAN header action
-record(ofp_action_pop_vlan, {
          seq = 3
         }).

%% Push MPLS header action
-record(ofp_action_push_mpls, {
          seq = 4,
          ethertype :: integer()
         }).

%% Push VLAN header action
-record(ofp_action_push_vlan, {
          seq = 5,
          ethertype :: integer()
         }).

%% Copy TTL outwards action
-record(ofp_action_copy_ttl_out, {
          seq = 6
         }).

%% Decrement MPLS TTL action
-record(ofp_action_dec_mpls_ttl, {
          seq = 7
         }).

%% Decrement IPv4 TTL action
-record(ofp_action_dec_nw_ttl, {
          seq = 8
         }).

%% Set MPLS TTL action
-record(ofp_action_set_mpls_ttl, {
          seq = 9,
          mpls_ttl :: integer()
         }).

%% Set IPv4 TTL action
-record(ofp_action_set_nw_ttl, {
          seq = 10,
          nw_ttl :: integer()
         }).

%% Set field action
-record(ofp_action_set_field, {
          seq = 11,
          field :: ofp_field()
         }).

%% Set queue action
-record(ofp_action_set_queue, {
          seq = 12,
          port :: integer(),
          queue_id :: integer()
         }).

%% Group action
-record(ofp_action_group, {
          seq = 13,
          group_id :: integer()
         }).

%% Output action
-record(ofp_action_output, {
          seq = 14,
          port :: ofp_port_no(),
          max_len = no_buffer :: ofp_buffer_id()
         }).

%% Experimenter action
-record(ofp_action_experimenter, {
          seq = 99,
          experimenter :: integer(),
          data = <<>> :: binary()
         }).

-type ofp_action_type() :: output
                         | group
                         | set_queue
                         | set_mpls_ttl
                         | dec_mpls_ttl
                         | set_nw_ttl
                         | dec_nw_ttl
                         | copy_ttl_out
                         | copy_ttl_in
                         | push_vlan
                         | pop_vlan
                         | push_mpls
                         | pop_mpls
                         | set_field
                         | experimenter.

-type ofp_action() :: #ofp_action_output{}
                    | #ofp_action_group{}
                    | #ofp_action_set_queue{}
                    | #ofp_action_set_mpls_ttl{}
                    | #ofp_action_dec_mpls_ttl{}
                    | #ofp_action_set_nw_ttl{}
                    | #ofp_action_dec_nw_ttl{}
                    | #ofp_action_copy_ttl_out{}
                    | #ofp_action_copy_ttl_in{}
                    | #ofp_action_push_vlan{}
                    | #ofp_action_pop_vlan{}
                    | #ofp_action_push_mpls{}
                    | #ofp_action_pop_mpls{}
                    | #ofp_action_set_field{}
                    | #ofp_action_experimenter{}.

%%% Other Structures -----------------------------------------------------------

%% Bucket for use in groups
-record(ofp_bucket, {
          weight :: integer(),
          watch_port :: integer(),
          watch_group :: integer(),
          actions = [] :: [ofp_action()]
         }).
-type ofp_bucket() :: #ofp_bucket{}.

%% Bucket counter for use in group stats
-record(ofp_bucket_counter, {
          packet_count = 0 :: integer(),
          byte_count   = 0 :: integer()
         }).
-type ofp_bucket_counter() :: #ofp_bucket_counter{}.

-type ofp_table_id() :: all
                      | integer().

%% Flow stats
-record(ofp_flow_stats, {
          table_id :: ofp_table_id(),
          duration_sec :: integer(),
          duration_nsec :: integer(),
          priority :: integer(),
          idle_timeout :: integer(),
          hard_timeout :: integer(),
          cookie :: binary(),
          packet_count :: integer(),
          byte_count :: integer(),
          match :: ofp_match(),
          instructions = [] :: [ofp_instruction()]
         }).
-type ofp_flow_stats() :: #ofp_flow_stats{}.

%% Table stats
-record(ofp_table_stats, {
          table_id :: ofp_table_id(),
          name :: binary(),
          match = [] :: [atom()],
          wildcards = [] :: [atom()],
          write_actions = [] :: [atom()],
          apply_actions = [] :: [atom()],
          write_setfields = [] :: [atom()],
          apply_setfields = [] :: [atom()],
          metadata_match :: binary(),
          metadata_write :: binary(),
          instructions = [] :: [atom()],
          config :: ofp_table_config(),
          max_entries :: integer(),
          active_count = 0 :: integer(),
          lookup_count = 0 :: integer(),
          matched_count = 0 :: integer()
         }).
-type ofp_table_stats() :: #ofp_table_stats{}.

%% Port stats
-record(ofp_port_stats, {
          port_no          :: ofp_port_no(),
          rx_packets   = 0 :: integer(),
          tx_packets   = 0 :: integer(),
          rx_bytes     = 0 :: integer(),
          tx_bytes     = 0 :: integer(),
          rx_dropped   = 0 :: integer(),
          tx_dropped   = 0 :: integer(),
          rx_errors    = 0 :: integer(),
          tx_errors    = 0 :: integer(),
          rx_frame_err = 0 :: integer(),
          rx_over_err  = 0 :: integer(),
          rx_crc_err   = 0 :: integer(),
          collisions   = 0 :: integer()
         }).
-type ofp_port_stats() :: #ofp_port_stats{}.

%% Queue stats
-record(ofp_queue_stats, {
          port_no        :: ofp_port_no(),
          queue_id       :: ofp_queue_id(),
          tx_bytes   = 0 :: integer(),
          tx_packets = 0 :: integer(),
          tx_errors  = 0 :: integer()
         }).
-type ofp_queue_stats() :: #ofp_queue_stats{}.

%% Group stats
-record(ofp_group_stats, {
          group_id :: ofp_group_id(),
          ref_count :: integer(),
          packet_count :: integer(),
          byte_count :: integer(),
          bucket_stats = [] :: [ofp_bucket_counter()]
         }).
-type ofp_group_stats() :: #ofp_group_stats{}.

%% Group desc stats
-record(ofp_group_desc_stats, {
          type :: atom(),
          group_id :: ofp_group_id(),
          buckets = [] :: [ofp_bucket()]
         }).
-type ofp_group_desc_stats() :: #ofp_group_desc_stats{}.

%%%-----------------------------------------------------------------------------
%%% Controller-to-Switch Messages
%%%-----------------------------------------------------------------------------

%%% Features (Handshake) -------------------------------------------------------

%% Features request
-record(ofp_features_request, {}).
-type ofp_features_request() :: #ofp_features_request{}.

-type ofp_switch_capability() :: flow_stats
                               | table_stats
                               | port_stats
                               | group_stats
                               | ip_reasm
                               | queue_stats
                               | port_blocked
                               | stp           %% OFP 1.0
                               | arp_match_ip. %% OFP 1.0/1.1

%% Switch features (Features reply)
-record(ofp_features_reply, {
          datapath_mac :: binary(),
          datapath_id :: integer(),
          n_buffers :: integer(),
          n_tables :: integer(),
          capabilities = [] :: [ofp_switch_capability()],
          actions = [] :: [ofp_action_type()],
          ports = [] :: [ofp_port()]
         }).
-type ofp_features_reply() :: #ofp_features_reply{}.

%%% Switch Configuration -------------------------------------------------------

%% Configuration request
-record(ofp_get_config_request, {}).
-type ofp_get_config_request() :: #ofp_get_config_request{}.

-type ofp_switch_configuration() :: frag_drop
                                  | frag_reasm
                                  | invalid_ttl_to_controller.

%% Configuration reply
-record(ofp_get_config_reply, {
          flags = [] :: [ofp_switch_configuration()],
          miss_send_len :: ofp_buffer_id()
         }).
-type ofp_get_config_reply() :: #ofp_get_config_reply{}.

%% Set configuration
-record(ofp_set_config, {
          flags = [] :: [ofp_switch_configuration()],
          miss_send_len :: ofp_buffer_id()
         }).
-type ofp_set_config() :: #ofp_set_config{}.

%%% Modify-State ---------------------------------------------------------------

-type ofp_flow_mod_command() :: add
                              | modify
                              | modify_strict
                              | delete
                              | delete_strict.

-type ofp_flow_mod_flag() :: send_flow_rem
                           | check_overlap
                           | reset_counts
                           | emerg.        %% OFP 1.0

%% Flow mod
-record(ofp_flow_mod, {
          cookie = <<0:64>> :: binary(),
          cookie_mask = <<0:64>> :: binary(),
          table_id = all :: ofp_table_id(),
          command :: ofp_flow_mod_command(),
          idle_timeout = 0 :: integer(),
          hard_timeout = 0 :: integer(),
          priority = 16#ffff :: integer(),
          buffer_id = no_buffer :: ofp_buffer_id(),
          out_port = any :: ofp_port_no(),
          out_group = any :: ofp_group_id(),
          flags = [] :: [ofp_flow_mod_flag()],
          match = #ofp_match{} :: ofp_match(),
          instructions = [] :: [ofp_instruction()]
         }).
-type ofp_flow_mod() :: #ofp_flow_mod{}.

-type ofp_group_mod_command() :: add
                               | modify
                               | delete.

-type ofp_group_type() :: all
                        | select
                        | indirect
                        | ff.

-type ofp_group_id() :: integer()
                      | any
                      | all.

%% Group mod
-record(ofp_group_mod, {
          command :: ofp_group_mod_command(),
          type :: ofp_group_type(),
          group_id :: ofp_group_id(),
          buckets = [] :: [ofp_bucket()]
         }).
-type ofp_group_mod() :: #ofp_group_mod{}.

%% Port mod
-record(ofp_port_mod, {
          port_no :: ofp_port_no(),
          hw_addr :: binary(),
          config = [] :: [ofp_port_config()],
          mask = [] :: [ofp_port_config()],
          advertise = [] :: [ofp_port_feature()]
         }).
-type ofp_port_mod() :: #ofp_port_mod{}.

-type ofp_table_config() :: continue
                          | drop
                          | controller.

%% Table mod
-record(ofp_table_mod, {
          table_id = all :: ofp_table_id(),
          config :: ofp_table_config()
         }).
-type ofp_table_mod() :: #ofp_table_mod{}.

%%% Read-State -----------------------------------------------------------------

-type ofp_stats_request_flags() :: any(). %% For future use
-type ofp_stats_reply_flags() :: more.

%% Request for desc stats
-record(ofp_desc_stats_request, {
          flags = [] :: [ofp_stats_request_flags()]
         }).
-type ofp_desc_stats_request() :: #ofp_desc_stats_request{}.

%% Desc stats
-record(ofp_desc_stats_reply, {
          flags = [] :: [ofp_stats_reply_flags()],
          mfr_desc :: binary(),
          hw_desc :: binary(),
          sw_desc :: binary(),
          serial_num :: binary(),
          dp_desc :: binary()
         }).
-type ofp_desc_stats_reply() :: #ofp_desc_stats_reply{}.

%% Request for flow stats
-record(ofp_flow_stats_request, {
          flags       = []           :: [ofp_stats_request_flags()],
          table_id    = all          :: ofp_table_id(),
          out_port    = any          :: ofp_port_no(),
          out_group   = any          :: ofp_group_id(),
          cookie      = <<0:64>>     :: binary(),
          cookie_mask = <<0:64>>     :: binary(),
          match       = #ofp_match{} :: ofp_match()
         }).
-type ofp_flow_stats_request() :: #ofp_flow_stats_request{}.

%% Flow stats reply
-record(ofp_flow_stats_reply, {
          flags = [] :: [ofp_stats_reply_flags()],
          stats = [] :: [ofp_flow_stats()]
         }).
-type ofp_flow_stats_reply() :: #ofp_flow_stats_reply{}.

%% Request for aggregate stats
-record(ofp_aggregate_stats_request, {
          flags = [] :: [ofp_stats_request_flags()],
          table_id = all :: ofp_table_id(),
          out_port = any :: ofp_port_no(),
          out_group = any :: ofp_group_id(),
          cookie = <<0:64>> :: binary(),
          cookie_mask = <<0:64>> :: binary(),
          match = #ofp_match{} :: ofp_match()}).
-type ofp_aggregate_stats_request() :: #ofp_aggregate_stats_request{}.

%% Aggregate stats reply
-record(ofp_aggregate_stats_reply, {
          flags = [] :: [ofp_stats_reply_flags()],
          packet_count = 0 :: integer(),
          byte_count = 0 :: integer(),
          flow_count = 0 :: integer()
         }).
-type ofp_aggregate_stats_reply() :: #ofp_aggregate_stats_reply{}.

%% Request for table stats
-record(ofp_table_stats_request, {
          flags = [] :: [ofp_stats_request_flags()]
         }).
-type ofp_table_stats_request() :: #ofp_table_stats_request{}.

%% Table stats reply
-record(ofp_table_stats_reply, {
          flags = [] :: [atom()],
          stats = [] :: [#ofp_table_stats{}]
         }).
-type ofp_table_stats_reply() :: #ofp_table_stats_reply{}.

%% Request for port stats
-record(ofp_port_stats_request, {
          flags = [] :: [ofp_stats_request_flags()],
          port_no :: ofp_port_no()
         }).
-type ofp_port_stats_request() :: #ofp_port_stats_request{}.

%% Port stats reply
-record(ofp_port_stats_reply, {
          flags = [] :: [ofp_stats_reply_flags()],
          stats = [] :: [ofp_port_stats()]
         }).
-type ofp_port_stats_reply() :: #ofp_port_stats_reply{}.

-type ofp_queue_id() :: integer()
                      | all.

%% Request for queue stats
-record(ofp_queue_stats_request, {
          flags = [] :: [ofp_stats_request_flags()],
          port_no = all :: ofp_port_no(),
          queue_id = all :: ofp_queue_id()
         }).
-type ofp_queue_stats_request() :: #ofp_queue_stats_request{}.

%% Queue stats reply
-record(ofp_queue_stats_reply, {
          flags = [] :: [ofp_stats_reply_flags()],
          stats = [] :: [ofp_queue_stats()]
         }).
-type ofp_queue_stats_reply() :: #ofp_queue_stats_reply{}.

%% Request for group stats
-record(ofp_group_stats_request, {
          flags = [] :: [ofp_stats_request_flags()],
          group_id = all :: ofp_group_id()
         }).
-type ofp_group_stats_request() :: #ofp_group_stats_request{}.

%% Group stats reply
-record(ofp_group_stats_reply, {
          flags = [] :: [ofp_stats_reply_flags()],
          stats = [] :: [ofp_group_stats()]
         }).
-type ofp_group_stats_reply() :: #ofp_group_stats_reply{}.

%% Request for group desc stats
-record(ofp_group_desc_stats_request, {
          flags = [] :: [ofp_stats_request_flags()]
         }).
-type ofp_group_desc_stats_request() :: #ofp_group_desc_stats_request{}.

%% Group desc stats reply
-record(ofp_group_desc_stats_reply, {
          flags = [] :: [ofp_stats_reply_flags()],
          stats = [] :: [ofp_group_desc_stats()]
         }).
-type ofp_group_desc_stats_reply() :: #ofp_group_desc_stats_reply{}.

%% Request for group features stats
-record(ofp_group_features_stats_request, {
          flags = [] :: [ofp_stats_request_flags()]
         }).
-type ofp_group_features_stats_request() :: #ofp_group_features_stats_request{}.

-type ofp_group_features_capabilities() :: select_weight
                                         | select_liveness
                                         | chaining
                                         | chaining_checks.

%% Group features stats reply
-record(ofp_group_features_stats_reply, {
          flags        = []               :: [ofp_stats_reply_flags()],
          types        = []               :: [atom()],
          capabilities = []               :: [ofp_group_features_capabilities()],
          max_groups   = {0,0,0,0}        :: {integer(), integer(),
                                              integer(), integer()},
          actions      = {[], [], [], []} :: {[atom()], [atom()],
                                              [atom()], [atom()]}
         }).
-type ofp_group_features_stats_reply() :: #ofp_group_features_stats_reply{}.

%% Request for experimenter stats
-record(ofp_experimenter_stats_request, {
          flags = [] :: [ofp_stats_request_flags()],
          experimenter :: integer(),
          exp_type :: integer(),
          data = <<>> :: binary()
         }).
-type ofp_experimenter_stats_request() :: #ofp_experimenter_stats_request{}.

%% Experimenter stats reply
-record(ofp_experimenter_stats_reply, {
          flags = [] :: [ofp_stats_reply_flags()],
          experimenter :: integer(),
          exp_type :: integer(),
          data = <<>> :: binary()
         }).
-type ofp_experimenter_stats_reply() :: #ofp_experimenter_stats_reply{}.

-type ofp_stats_request() :: ofp_desc_stats_request()
                           | ofp_flow_stats_request()
                           | ofp_aggregate_stats_request()
                           | ofp_table_stats_request()
                           | ofp_port_stats_request()
                           | ofp_queue_stats_request()
                           | ofp_group_stats_request()
                           | ofp_group_desc_stats_request()
                           | ofp_group_features_stats_request()
                           | ofp_experimenter_stats_request().

-type ofp_stats_reply() :: ofp_desc_stats_reply()
                         | ofp_flow_stats_reply()
                         | ofp_aggregate_stats_reply()
                         | ofp_table_stats_reply()
                         | ofp_port_stats_reply()
                         | ofp_queue_stats_reply()
                         | ofp_group_stats_reply()
                         | ofp_group_desc_stats_reply()
                         | ofp_group_features_stats_reply()
                         | ofp_experimenter_stats_reply().

%%% Queue Configuration --------------------------------------------------------

%% Get queue config request message
-record(ofp_queue_get_config_request, {
          port :: ofp_port_no()
         }).
-type ofp_queue_get_config_request() :: #ofp_queue_get_config_request{}.

%% Get queue config reply message
-record(ofp_queue_get_config_reply, {
          port :: ofp_port_no(),
          queues = [] :: [ofp_packet_queue()]
         }).
-type ofp_queue_get_config_reply() :: #ofp_queue_get_config_reply{}.

%%% Packet-out -----------------------------------------------------------------

%% Send packet
-record(ofp_packet_out, {
          buffer_id = no_buffer :: ofp_buffer_id(),
          in_port = controller :: controller,
          actions = [] :: [ofp_action()],
          data = <<>> :: binary()
         }).
-type ofp_packet_out() :: #ofp_packet_out{}.

%%% Barrier --------------------------------------------------------------------

%% Barrier request
-record(ofp_barrier_request, {}).
-type ofp_barrier_request() :: #ofp_barrier_request{}.

%% Barrier reply
-record(ofp_barrier_reply, {}).
-type ofp_barrier_reply() :: #ofp_barrier_reply{}.

%%% Role Request ---------------------------------------------------------------

-type ofp_controller_role() :: nochange
                             | equal
                             | master
                             | slave.

%% Role request messages
-record(ofp_role_request, {
          role :: ofp_controller_role(),
          generation_id :: integer()
         }).
-type ofp_role_request() :: #ofp_role_request{}.

%% Role reply message
-record(ofp_role_reply, {
          role :: ofp_controller_role(),
          generation_id :: integer()
         }).
-type ofp_role_reply() :: #ofp_role_reply{}.

%%%-----------------------------------------------------------------------------
%%% Asynchronous Messages
%%%-----------------------------------------------------------------------------

-type ofp_packet_in_reason() :: no_match
                              | action
                              | invalid_ttl.

-type ofp_buffer_id() :: integer()
                       | no_buffer.

%% Packet-in
-record(ofp_packet_in, {
          buffer_id = no_buffer :: ofp_buffer_id(),
          in_port :: ofp_port_no(),                 %% OFP 1.0
          in_phy_port :: ofp_port_no(),             %% OFP 1.0
          reason :: ofp_packet_in_reason(),
          table_id :: integer(),
          match :: ofp_match(),
          data = <<>> :: binary()
         }).
-type ofp_packet_in() :: #ofp_packet_in{}.

-type ofp_flow_removed_reason() :: idle_timeout
                                 | hard_timeout
                                 | delete
                                 | group_delete.

%% Flow removed
-record(ofp_flow_removed, {
          cookie :: binary(),
          priority :: integer(),
          reason :: ofp_flow_removed_reason(),
          table_id :: integer(),
          duration_sec :: integer(),
          duration_nsec :: integer(),
          idle_timeout :: integer(),
          hard_timeout :: integer(),
          packet_count :: integer(),
          byte_count :: integer(),
          match :: ofp_match()
         }).
-type ofp_flow_removed() :: #ofp_flow_removed{}.

-type ofp_port_status_reason() :: add
                                | delete
                                | modify.

%% Port status change
-record(ofp_port_status, {
          reason :: ofp_port_status_reason(),
          desc :: ofp_port()
         }).
-type ofp_port_status() :: #ofp_port_status{}.

%% -type ofp_error_type() :: ...
%% -type ofp_bad_request_code() :: ...
%% -type ofp_error_code() :: bad_request_code()
%%                         | ...

%% Error message
-record(ofp_error, {
          type :: atom(),
          code :: atom(),
          data = <<>> :: binary()
         }).

%% Experimenter error message
-record(ofp_error_experimenter, {
          exp_type :: integer(),
          experimenter :: integer(),
          data = <<>> :: binary()
         }).

-type ofp_error() :: #ofp_error{}
                   | #ofp_error_experimenter{}.

%%%-----------------------------------------------------------------------------
%%% Symmetric Messages
%%%-----------------------------------------------------------------------------

%% Hello message
-record(ofp_hello, {}).
-type ofp_hello() :: #ofp_hello{}.

%% Echo Request
-record(ofp_echo_request, {
          data = <<>> :: binary()
         }).
-type ofp_echo_request() :: #ofp_echo_request{}.

%% Echo Reply
-record(ofp_echo_reply, {
          data = <<>> :: binary()
         }).
-type ofp_echo_reply() :: #ofp_echo_reply{}.

%% Experimenter
-record(ofp_experimenter, {
          experimenter :: integer(),
          exp_type :: integer(),
          data = <<>> :: binary()
         }).
-type ofp_experimenter() :: #ofp_experimenter{}.

-type ofp_message_body() :: ofp_hello()
                          | ofp_error()
                          | ofp_echo_request()
                          | ofp_echo_reply()
                          | ofp_experimenter()
                          | ofp_features_request()
                          | ofp_features_reply()
                          | ofp_get_config_request()
                          | ofp_get_config_reply()
                          | ofp_set_config()
                          | ofp_packet_in()
                          | ofp_flow_removed()
                          | ofp_port_status()
                          | ofp_packet_out()
                          | ofp_flow_mod()
                          | ofp_group_mod()
                          | ofp_port_mod()
                          | ofp_table_mod()
                          | ofp_stats_request()
                          | ofp_stats_reply()
                          | ofp_barrier_request()
                          | ofp_barrier_reply()
                          | ofp_queue_get_config_request()
                          | ofp_queue_get_config_reply()
                          | ofp_role_request()
                          | ofp_role_reply().
