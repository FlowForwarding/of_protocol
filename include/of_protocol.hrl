%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%%%-----------------------------------------------------------------------------

-include("ofp_structures.hrl").

%%%-----------------------------------------------------------------------------
%%% Controller-to-Switch Messages
%%%-----------------------------------------------------------------------------

%%% Features -------------------------------------------------------------------

%% Features request
-define(FEATURES_REQUEST_SIZE, 8).
-record(features_request, {
          header = #header{} :: #header{}
         }).

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

%% Configuration reply
-define(GET_CONFIG_REPLY_SIZE, 12).
-record(get_config_reply, {
          header = #header{} :: #header{},
          flags = [] :: [atom()],
          miss_send_len :: integer()
         }).

%% Set configuration
-define(SET_CONFIG_SIZE, 12).
-record(set_config, {
          header = #header{} :: #header{},
          flags = [] :: [atom()],
          miss_send_len :: integer()
         }).

%% Configuration flags
-define(OFPC_FRAG_NORMAL, 0).
-define(OFPC_FRAG_DROP, 0).
-define(OFPC_FRAG_REASM, 1).
-define(OFPC_INVALID_TTL_TO_CONTROLLER, 2).
-define(OFPC_FRAG_MASK, 3).

%%% Modify-State ---------------------------------------------------------------

%% Configure/Modify behavior of a flow table
-record(table_mod, {
          header = #header{} :: #header{},
          table_id,
          config
         }).

%% Flow setup and teardown (controller -> datapath)
-record(flow_mod, {
          header = #header{} :: #header{},
          cookie,
          cookie_mask,
          table_id,
          command,
          idle_timeout,
          hard_timeout,
          priority,
          buffer_id,
          out_port,
          out_group,
          flags,
          match :: #match{},
          instructions :: list()
         }).

%% Bucket for use in groups
-record(bucket, {
          length :: integer(),
          weight :: integer(),
          watch_port,
          watch_group,
          actions :: [#action_header{}]
         }).

%% Group setup and teardown (controller -> datapath)
-record(group_mod, {
          header = #header{} :: #header{},
          command,
          type,
          group_id,
          buckets = [#bucket{}]
         }).

%% Modify behavior of the physical port
-record(port_mod, {
          header = #header{} :: #header{},
          port_no,
          hw_addr,
          config,
          mask,
          advertise
         }).

%%% Read-State -----------------------------------------------------------------

-record(stats_request, {
          header = #header{} :: #header{},
          type :: atom(),
          flags :: list(atom()),
          body :: term() %% request type dependent
         }).

-record(stats_reply, {}).

-record(flow_stats_request, {
          table_id :: integer(),
          out_port :: integer(),
          out_group :: integer(),
          cookie :: integer(),
          cookie_mask :: integer(),
          match :: #match{}}).

-record(flow_stats, {}).

-record(aggregate_stats_request, {
          table_id :: integer(),
          out_port :: integer(),
          out_group :: integer(),
          cookie :: integer(),
          cookie_mask :: integer(),
          match :: #match{}}).

-record(aggregate_stats_reply, {}).

-record(table_stats, {
          table_id :: integer(),
          name :: binary(),
          match :: list(),
          wildcards :: list(),
          write_actions :: list(),
          apply_actions :: list(),
          write_setfields :: list(),
          apply_setfields :: list(),
          metadata_match :: integer(),
          metadata_write :: integer(),
          instructions :: list(),
          config :: list(),
          max_entries :: integer(),
          active_count :: integer(),
          lookup_count :: integer(),
          matched_count :: integer()
         }).

-record(port_stats_request, {
          port_no :: integer()
         }).

-record(port_stats, {}).

-record(queue_stats_request, {
          port_no :: integer(),
          queue_id :: integer()
         }).

-record(queue_stats, {}).

-record(group_stats_request, {
          group_id :: integer()
         }).

-record(group_stats, {}).
-record(bucket_counter, {}).
-record(group_desc_stats, {}).

-record(experimenter_stats_header, {
          experimenter :: integer(),
          exp_type :: integer(),
          additional_data :: binary()
         }).

%% and more...

%%% Packet-out -----------------------------------------------------------------

%% Send packet (controller -> datapath)
-record(packet_out, {
          header = #header{} :: #header{},
          buffer_id,
          in_port,
          actions :: [#action_header{}]
         }).

%%% Barrier ----------------------------------------------------------

-record(barrier, {
          header = #header{} :: #header{}
         }).

%%%-----------------------------------------------------------------------------
%%% Asynchronous Messages
%%%-----------------------------------------------------------------------------

%% Packet received on port
-record(packet_in, {
          header = #header{} :: #header{},
          buffer_id,
          total_len,
          reason,
          table_id,
          match :: #match{},
          data
         }).

%% Flow removed
-record(flow_removed, {
          header = #header{} :: #header{},
          cookie,
          priority,
          reason,
          table_id,
          duration_sec :: integer(),
          duration_nsec :: integer(),
          idle_timeout :: integer(),
          hard_timeout :: integer(),
          packet_count :: integer(),
          byte_count :: integer(),
          match :: #match{}
         }).

%% A physical port has changed in the datapath
-record(port_status, {
          header = #header{} :: #header{},
          reason,
          desc :: #port{}
         }).

%% Error message
-define(ERROR_MSG_SIZE, 12).
-record(error_msg, {
          header = #header{} :: #header{},
          type :: atom(),
          code :: atom(),
          data :: binary()
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
          data :: binary()
         }).

%%%-----------------------------------------------------------------------------
%%% Symmetric Messages
%%%-----------------------------------------------------------------------------

%% Hello message
-define(HELLO_SIZE, 8).
-record(hello, {
          header = #header{} :: #header{}
         }).

%% Echo Request
-define(ECHO_REQUEST_SIZE, 8).
-record(echo_request, {
          header = #header{} :: #header{},
          data :: binary()
         }).

%% Echo Reply
-define(ECHO_REPLY_SIZE, 8).
-record(echo_reply, {
          header = #header{} :: #header{},
          data :: binary()
         }).

%% Experimenter
-record(experimenter_header, {
          header = #header{} :: #header{},
          experimenter,
          exp_type
         }).
