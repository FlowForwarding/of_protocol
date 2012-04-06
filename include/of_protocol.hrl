%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%%%-----------------------------------------------------------------------------

-include_lib("of_protocol/include/ofp_structures.hrl").

-record(parser, {
          stack = <<>> :: binary()
         }).

%%%-----------------------------------------------------------------------------
%%% Controller-to-Switch Messages
%%%-----------------------------------------------------------------------------

%%% Features -------------------------------------------------------------------

%% Features request
-define(FEATURES_REQUEST_SIZE, 8).
-record(features_request, {
          header = #header{} :: #header{}
         }).
-type features_request() :: #features_request{}.

%% Switch features (Features reply)
-define(FEATURES_REPLY_SIZE, 32).
-record(features_reply, {
          header = #header{} :: #header{},
          datapath_mac :: binary(),
          datapath_id :: integer(),
          n_buffers :: integer(),
          n_tables :: integer(),
          capabilities = [] :: [atom()],
          ports = [] :: [#port{}]
         }).
-type features_reply() :: #features_reply{}.

%% Capabilities supported by the datapath
-define(OFPC_FLOW_STATS, 0).
-define(OFPC_TABLE_STATS, 1).
-define(OFPC_PORT_STATS, 2).
-define(OFPC_GROUP_STATS, 3).
-define(OFPC_IP_REASM, 5).
-define(OFPC_QUEUE_STATS, 6).
-define(OFPC_PORT_BLOCKED, 8).

%%% Configuration --------------------------------------------------------------

%% Configuration request
-define(GET_CONFIG_REQUEST_SIZE, 8).
-record(get_config_request, {
          header = #header{} :: #header{}
         }).
-type get_config_request() :: #get_config_request{}.

%% Configuration reply
-define(GET_CONFIG_REPLY_SIZE, 12).
-record(get_config_reply, {
          header = #header{} :: #header{},
          flags = [] :: [atom()],
          miss_send_len :: integer()
         }).
-type get_config_reply() :: #get_config_reply{}.

%% Set configuration
-define(SET_CONFIG_SIZE, 12).
-record(set_config, {
          header = #header{} :: #header{},
          flags = [] :: [atom()],
          miss_send_len :: integer()
         }).
-type set_config() :: #set_config{}.

%% Configuration flags
-type table_config() :: drop | controller | continue.
-define(OFPC_FRAG_NORMAL, 0).
-define(OFPC_FRAG_DROP, 0).
-define(OFPC_FRAG_REASM, 1).
-define(OFPC_INVALID_TTL_TO_CONTROLLER, 2).
-define(OFPC_FRAG_MASK, 3).

%%% Modify-State ---------------------------------------------------------------

%% Configure/Modify behavior of a flow table
-define(TABLE_MOD_SIZE, 16).
-record(table_mod, {
          header = #header{} :: #header{},
          table_id :: integer() | atom(),
          config = drop :: table_config()
         }).
-type table_mod() :: #table_mod{}.

%% Table numbering
-define(OFPTT_MAX, 16#fe).
-define(OFPTT_ALL, 16#ff).

%% Table config
-define(OFPTC_TABLE_MISS_CONTINUE, 0).
-define(OFPTC_TABLE_MISS_DROP, 1).
-define(OFPTC_TABLE_MISS_MASK, 3).

%% Flow setup and teardown
-define(FLOW_MOD_SIZE, 56).
-record(flow_mod, {
          header = #header{} :: #header{},
          cookie :: binary(),
          cookie_mask :: binary(),
          table_id :: table_id(),
          command :: flow_mod_command(),
          idle_timeout :: integer(),
          hard_timeout :: integer(),
          priority :: integer(),
          buffer_id :: integer(),
          out_port :: integer() | atom(),
          out_group :: integer() | atom(),
          flags = [] :: [flow_mod_flag()],
          match :: match(),
          instructions = [] :: [instruction()]
         }).
-type flow_mod() :: #flow_mod{}.

%% Flow mod commands
-type flow_mod_command() :: add
                          | modify
                          | modify_strict
                          | delete
                          | delete_strict.
-define(OFPFC_ADD, 0).
-define(OFPFC_MODIFY, 1).
-define(OFPFC_MODIFY_STRICT, 2).
-define(OFPFC_DELETE, 3).
-define(OFPFC_DELETE_STRICT, 4).

%% Flow mod flags
-type flow_mod_flag() :: send_flow_rem | check_overlap | reset_counts.
-define(OFPFF_SEND_FLOW_REM, 0).
-define(OFPFF_CHECK_OVERLAP, 1).
-define(OFPFF_RESET_COUNTS, 2).

%% Group setup and teardown
-define(GROUP_MOD_SIZE, 16).
-record(group_mod, {
          header = #header{} :: #header{},
          command :: atom(),
          type :: atom(),
          group_id :: integer() | atom(),
          buckets = [] :: [#bucket{}]
         }).
-type group_mod() :: #group_mod{}.

%% Group commands
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

%% Modify behavior of the physical port
-define(PORT_MOD_SIZE, 40).
-record(port_mod, {
          header = #header{} :: #header{},
          port_no :: integer() | atom(),
          hw_addr :: binary(),
          config = [] :: [atom()],
          mask = [] :: [atom()],
          advertise = [] :: [atom()]
         }).
-type port_mod() :: #port_mod{}.

%%% Read-State -----------------------------------------------------------------

%% Request for desc stats
-define(DESC_STATS_REQUEST_SIZE, 16).
-record(desc_stats_request, {
          header = #header{} :: #header{},
          flags = [] :: [atom()]
         }).
-type desc_stats_request() :: #desc_stats_request{}.

%% Desc stats
-define(DESC_STATS_REPLY_SIZE, 1072).
-record(desc_stats_reply, {
          header = #header{} :: #header{},
          flags = [] :: [atom()],
          mfr_desc :: binary(),
          hw_desc :: binary(),
          sw_desc :: binary(),
          serial_num :: binary(),
          dp_desc :: binary()
         }).
-type desc_stats_reply() :: #desc_stats_reply{}.

%% Request for flow stats
-define(FLOW_STATS_REQUEST_SIZE, 56).
-record(flow_stats_request, {
          header = #header{} :: #header{},
          flags = [] :: [atom()],
          table_id :: table_id(),
          out_port :: port_no(),
          out_group :: group_id(),
          cookie :: binary(),
          cookie_mask :: binary(),
          match :: match()
         }).
-type flow_stats_request() :: #flow_stats_request{}.

%% Flow stats reply
-define(FLOW_STATS_REPLY_SIZE, 16).
-record(flow_stats_reply, {
          header = #header{} :: #header{},
          flags = [] :: [atom()],
          stats = [] :: [#flow_stats{}]
         }).
-type flow_stats_reply() :: #flow_stats_reply{}.

%% Request for aggregate stats
-define(AGGREGATE_STATS_REQUEST_SIZE, 56).
-record(aggregate_stats_request, {
          header = #header{} :: #header{},
          flags :: [atom()],
          table_id :: table_id(),
          out_port :: port_no(),
          out_group :: group_id(),
          cookie :: binary(),
          cookie_mask :: binary(),
          match :: match()}).
-type aggregate_stats_request() :: #aggregate_stats_request{}.

%% Aggregate stats reply
-define(AGGREGATE_STATS_REPLY_SIZE, 40).
-record(aggregate_stats_reply, {
          header = #header{} :: #header{},
          flags :: [atom()],
          packet_count :: integer(),
          byte_count :: integer(),
          flow_count :: integer()
         }).
-type aggregate_stats_reply() :: #aggregate_stats_reply{}.

%% Request for table stats
-define(TABLE_STATS_REQUEST_SIZE, 16).
-record(table_stats_request, {
          header = #header{} :: #header{},
          flags :: [atom()]
         }).
-type table_stats_request() :: #table_stats_request{}.

%% Table stats reply
-define(TABLE_STATS_REPLY_SIZE, 16).
-record(table_stats_reply, {
          header = #header{} :: #header{},
          flags :: [atom()],
          stats = [] :: [#table_stats{}]
         }).
-type table_stats_reply() :: #table_stats_reply{}.

%% Request for port stats
-define(PORT_STATS_REQUEST_SIZE, 24).
-record(port_stats_request, {
          header = #header{} :: #header{},
          flags :: [atom()],
          port_no :: port_no()
         }).
-type port_stats_request() :: #port_stats_request{}.

%% Port stats reply
-define(PORT_STATS_REPLY_SIZE, 16).
-record(port_stats_reply, {
          header = #header{} :: #header{},
          flags :: [atom()],
          stats = [] :: [#port_stats{}]
         }).
-type port_stats_reply() :: #port_stats_reply{}.

%% Request for queue stats
-define(QUEUE_STATS_REQUEST_SIZE, 24).
-record(queue_stats_request, {
          header = #header{} :: #header{},
          flags :: [atom()],
          port_no :: port_no(),
          queue_id :: queue_id()
         }).
-type queue_stats_request() :: #queue_stats_request{}.

%% Queue stats reply
-define(QUEUE_STATS_REPLY_SIZE, 16).
-record(queue_stats_reply, {
          header = #header{} :: #header{},
          flags :: [atom()],
          stats = [] :: [#queue_stats{}]
         }).
-type queue_stats_reply() :: #queue_stats_reply{}.

%% Request for group stats
-define(GROUP_STATS_REQUEST_SIZE, 24).
-record(group_stats_request, {
          header = #header{} :: #header{},
          flags :: [atom()],
          group_id :: group_id()
         }).
-type group_stats_request() :: #group_stats_request{}.

%% Group stats reply
-define(GROUP_STATS_REPLY_SIZE, 16).
-record(group_stats_reply, {
          header = #header{} :: #header{},
          flags :: [atom()],
          stats = [] :: [#group_stats{}]
         }).
-type group_stats_reply() :: #group_stats_reply{}.

%% Request for group desc stats
-define(GROUP_DESC_STATS_REQUEST_SIZE, 16).
-record(group_desc_stats_request, {
          header = #header{} :: #header{},
          flags :: [atom()]
         }).
-type group_desc_stats_request() :: #group_desc_stats_request{}.

%% Group desc stats reply
-define(GROUP_DESC_STATS_REPLY_SIZE, 16).
-record(group_desc_stats_reply, {
          header = #header{} :: #header{},
          flags :: [atom()],
          stats = [] :: [#group_desc_stats{}]
         }).
-type group_desc_stats_reply() :: #group_desc_stats_reply{}.

%% Request for group features stats
-define(GROUP_FEATURES_STATS_REQUEST_SIZE, 16).
-record(group_features_stats_request, {
          header = #header{} :: #header{},
          flags :: [atom()]
         }).
-type group_features_stats_request() :: #group_features_stats_request{}.

%% Group features stats reply
-define(GROUP_FEATURES_STATS_REPLY_SIZE, 56).
-record(group_features_stats_reply, {
          header = #header{} :: #header{},
          flags :: [atom()],
          types :: [atom()],
          capabilities :: [atom()],
          max_groups :: {integer(), integer(), integer(), integer()},
          actions :: {[atom()], [atom()], [atom()], [atom()]}
         }).
-type group_features_stats_reply() :: #group_features_stats_reply{}.

%% Group capabilities
-define(OFPGFC_SELECT_WEIGHT, 0).
-define(OFPGFC_SELECT_LIVENESS, 1).
-define(OFPGFC_CHAINING, 2).
-define(OFPGFC_CHAINING_CHECKS, 3).

%% Request for experimenter stats
-define(EXPERIMENTER_STATS_REQUEST_SIZE, 24).
-record(experimenter_stats_request, {
          header = #header{} :: #header{},
          flags :: [atom()],
          experimenter :: integer(),
          exp_type :: integer(),
          data = <<>> :: binary()
         }).
-type experimenter_stats_request() :: #experimenter_stats_request{}.

%% Experimenter stats reply
-define(EXPERIMENTER_STATS_REPLY_SIZE, 24).
-record(experimenter_stats_reply, {
          header = #header{} :: #header{},
          flags :: [atom()],
          experimenter :: integer(),
          exp_type :: integer(),
          data = <<>> :: binary()
         }).
-type experimenter_stats_reply() :: #experimenter_stats_reply{}.

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

-type stats_request() :: desc_stats_request() | flow_stats_request() |
                         aggregate_stats_request() | table_stats_request() |
                         port_stats_request() | queue_stats_request() |
                         group_stats_request() | group_desc_stats_request() |
                         group_features_stats_request() |
                         experimenter_stats_request().

-type stats_reply() :: desc_stats_reply() | flow_stats_reply() |
                       aggregate_stats_reply() | table_stats_reply() |
                       port_stats_reply() | queue_stats_reply() |
                       group_stats_reply() | group_desc_stats_reply() |
                       group_features_stats_reply() |
                       experimenter_stats_reply().

%%% Queue Configuration --------------------------------------------------------

%% Get queue config request message
-define(QUEUE_GET_CONFIG_REQUEST_SIZE, 16).
-record(queue_get_config_request, {
          header = #header{} :: #header{},
          port :: integer() | atom()
         }).
-type queue_get_config_request() :: #queue_get_config_request{}.

%% Get queue config reply message
-define(QUEUE_GET_CONFIG_REPLY_SIZE, 16).
-record(queue_get_config_reply, {
          header = #header{} :: #header{},
          port :: integer() | atom(),
          queues = [] :: [#packet_queue{}]
         }).
-type queue_get_config_reply() :: #queue_get_config_reply{}.

%% Queue numbering
-define(OFPQ_MAX, 16#fffffffe).
-define(OFPQ_ALL, 16#ffffffff).

%%% Packet-out -----------------------------------------------------------------

%% Send packet
-define(PACKET_OUT_SIZE, 24).
-record(packet_out, {
          header = #header{} :: #header{},
          buffer_id :: integer(),
          in_port :: integer() | atom(),
          actions = [] :: [action()],
          data = <<>> :: binary()
         }).
-type packet_out() :: #packet_out{}.

%%% Barrier --------------------------------------------------------------------

%% Barrier request
-define(BARRIER_REQUEST_SIZE, 8).
-record(barrier_request, {
          header = #header{} :: #header{}
         }).
-type barrier_request() :: #barrier_request{}.

%% Barrier reply
-define(BARRIER_REPLY_SIZE, 8).
-record(barrier_reply, {
          header = #header{} :: #header{}
         }).
-type barrier_reply() :: #barrier_reply{}.

%%% Role Request ---------------------------------------------------------------

%% Role request messages
-define(ROLE_REQUEST_SIZE, 24).
-record(role_request, {
          header = #header{} :: #header{},
          role :: atom(),
          generation_id :: integer()
         }).
-type role_request() :: #role_request{}.

%% Role reply message
-define(ROLE_REPLY_SIZE, 24).
-record(role_reply, {
          header = #header{} :: #header{},
          role :: atom(),
          generation_id :: integer()
         }).
-type role_reply() :: #role_reply{}.

%% Controller roles
-define(OFPCR_ROLE_NOCHANGE, 0).
-define(OFPCR_ROLE_EQUAL, 1).
-define(OFPCR_ROLE_MASTER, 2).
-define(OFPCR_ROLE_SLAVE, 3).

%%%-----------------------------------------------------------------------------
%%% Asynchronous Messages
%%%-----------------------------------------------------------------------------

%% Packet received on port
-define(PACKET_IN_SIZE, 24).
-record(packet_in, {
          header = #header{} :: #header{},
          buffer_id :: integer(),
          reason :: atom(),
          table_id :: integer(),
          match :: match(),
          data = <<>> :: binary()
         }).
-type packet_in() :: #packet_in{}.

%% Reason packet is being sent
-define(OFPR_NO_MATCH, 0).
-define(OFPR_ACTION, 1).
-define(OFPR_INVALID_TTL, 2).

%% Flow removed
-define(FLOW_REMOVED_SIZE, 56).
-record(flow_removed, {
          header = #header{} :: #header{},
          cookie :: binary(),
          priority :: integer(),
          reason :: atom(),
          table_id :: integer(),
          duration_sec :: integer(),
          duration_nsec :: integer(),
          idle_timeout :: integer(),
          hard_timeout :: integer(),
          packet_count :: integer(),
          byte_count :: integer(),
          match :: match()
         }).
-type flow_removed() :: #flow_removed{}.

%% Flow Removed reasons
-define(OFPRR_IDLE_TIMEOUT, 0).
-define(OFPRR_HARD_TIMEOUT, 1).
-define(OFPRR_DELETE, 2).
-define(OFPRR_GROUP_DELETE, 3).

%% A physical port has changed in the datapath
-define(PORT_STATUS_SIZE, 80).
-record(port_status, {
          header = #header{} :: #header{},
          reason :: atom(),
          desc :: #port{}
         }).
-type port_status() :: #port_status{}.

%% Reason for Port Status
-define(OFPPR_ADD, 0).
-define(OFPPR_DELETE, 1).
-define(OFPPR_MODIFY, 2).

%% Error message
-define(ERROR_MSG_SIZE, 12).
-record(error_msg, {
          header = #header{} :: #header{},
          type :: atom(),
          code :: atom(),
          data = <<>> :: binary()
         }).

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

%% Experimenter error message
-define(ERROR_EXPERIMENTER_MSG_SIZE, 16).
-record(error_experimenter_msg, {
          header = #header{} :: #header{},
          exp_type :: integer(),
          experimenter :: integer(),
          data = <<>> :: binary()
         }).
-type error_experimenter_msg() :: #error_experimenter_msg{}.

-type error_msg() :: #error_msg{} | error_experimenter_msg().

%%%-----------------------------------------------------------------------------
%%% Symmetric Messages
%%%-----------------------------------------------------------------------------

%% Hello message
-define(HELLO_SIZE, 8).
-record(hello, {
          header = #header{} :: #header{}
         }).
-type hello() :: #hello{}.

%% Echo Request
-define(ECHO_REQUEST_SIZE, 8).
-record(echo_request, {
          header = #header{} :: #header{},
          data = <<>> :: binary()
         }).
-type echo_request() :: #echo_request{}.

%% Echo Reply
-define(ECHO_REPLY_SIZE, 8).
-record(echo_reply, {
          header = #header{} :: #header{},
          data = <<>> :: binary()
         }).
-type echo_reply() :: #echo_reply{}.

%% Experimenter
-define(EXPERIMENTER_SIZE, 16).
-record(experimenter, {
          header = #header{} :: #header{},
          experimenter :: integer(),
          exp_type :: integer(),
          data = <<>> :: binary()
         }).
-type experimenter() :: #experimenter{}.

-type ofp_message() :: hello() | error_msg() | echo_request() | echo_reply() |
                       experimenter() | features_request() | features_reply() |
                       get_config_request() | get_config_reply() |
                       set_config() | packet_in() | flow_removed() |
                       port_status() | packet_out() | flow_mod() | group_mod() |
                       table_mod() | stats_request() | stats_reply() |
                       barrier_request() | barrier_reply() |
                       queue_get_config_request() | queue_get_config_reply() |
                       role_request() | role_reply().
