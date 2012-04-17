%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc Module for mapping between atoms and bits for OFP 1.2.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_v3_map).

%% Helper functions
-export([tlv_length/1,
         oxm_field/2,
         get_experimenter_bit/1]).

%% Mapping functions
-export([msg_type/1]).
-export([port_config/1,
         port_state/1,
         encode_port_no/1,
         decode_port_no/1,
         port_feature/1]).
-export([error_type/1,
         hello_failed/1,
         bad_request/1,
         bad_action/1,
         bad_instruction/1,
         bad_match/1,
         flow_mod_failed/1,
         group_mod_failed/1,
         port_mod_failed/1,
         table_mod_failed/1,
         queue_op_failed/1,
         switch_config_failed/1,
         role_request_failed/1,
         capability/1,
         configuration/1,
         reason/1,
         removed_reason/1,
         port_reason/1,
         match_type/1,
         oxm_class/1,
         oxm_field/1,
         action_type/1,
         table_config/1,
         flow_command/1,
         flow_flag/1,
         instruction_type/1,
         group_type/1,
         group_command/1,
         controller_role/1,
         queue_property/1,
         stats_type/1,
         stats_request_flag/1,
         stats_reply_flag/1,
         group_capability/1]).

-export([encode_group_id/1, decode_group_id/1,
         encode_table_id/1, decode_table_id/1,
         encode_queue_id/1, decode_queue_id/1,
         encode_buffer_id/1, decode_buffer_id/1,
         encode_max_length/1, decode_max_length/1]).

-include("of_protocol.hrl").
-include("ofp_v3.hrl").

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
msg_type(role_request)                   -> ?OFPT_ROLE_REQUEST;
msg_type(?OFPT_ROLE_REQUEST)             -> role_request;
msg_type(role_reply)                     -> ?OFPT_ROLE_REPLY;
msg_type(?OFPT_ROLE_REPLY)               -> role_reply;
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

%%% Rest -----------------------------------------------------------------------

error_type(hello_failed)                -> ?OFPET_HELLO_FAILED;
error_type(?OFPET_HELLO_FAILED)         -> hello_failed;
error_type(bad_request)                 -> ?OFPET_BAD_REQUEST;
error_type(?OFPET_BAD_REQUEST)          -> bad_request;
error_type(bad_action)                  -> ?OFPET_BAD_ACTION;
error_type(?OFPET_BAD_ACTION)           -> bad_action;
error_type(bad_instruction)             -> ?OFPET_BAD_INSTRUCTION;
error_type(?OFPET_BAD_INSTRUCTION)      -> bad_instruction;
error_type(bad_match)                   -> ?OFPET_BAD_MATCH;
error_type(?OFPET_BAD_MATCH)            -> bad_match;
error_type(flow_mod_failed)             -> ?OFPET_FLOW_MOD_FAILED;
error_type(?OFPET_FLOW_MOD_FAILED)      -> flow_mod_failed;
error_type(group_mod_failed)            -> ?OFPET_GROUP_MOD_FAILED;
error_type(?OFPET_GROUP_MOD_FAILED)     -> group_mod_failed;
error_type(port_mod_failed)             -> ?OFPET_PORT_MOD_FAILED;
error_type(?OFPET_PORT_MOD_FAILED)      -> port_mod_failed;
error_type(table_mod_failed)            -> ?OFPET_TABLE_MOD_FAILED;
error_type(?OFPET_TABLE_MOD_FAILED)     -> table_mod_failed;
error_type(queue_op_failed)             -> ?OFPET_QUEUE_OP_FAILED;
error_type(?OFPET_QUEUE_OP_FAILED)      -> queue_op_failed;
error_type(switch_config_failed)        -> ?OFPET_SWITCH_CONFIG_FAILED;
error_type(?OFPET_SWITCH_CONFIG_FAILED) -> switch_config_failed;
error_type(role_request_failed)         -> ?OFPET_ROLE_REQUEST_FAILED;
error_type(?OFPET_ROLE_REQUEST_FAILED)  -> role_request_failed;
error_type(experimenter)                -> ?OFPET_EXPERIMENTER;
error_type(?OFPET_EXPERIMENTER)         -> experimenter;
error_type(Type) when is_atom(Type)     -> throw({bad_type, Type});
error_type(Type) when is_integer(Type)  -> throw({bad_value, Type}).

hello_failed(incompatible)               -> ?OFPHFC_INCOMPATIBLE;
hello_failed(?OFPHFC_INCOMPATIBLE)       -> incompatible;
hello_failed(eperm)                      -> ?OFPHFC_EPERM;
hello_failed(?OFPHFC_EPERM)              -> eperm;
hello_failed(Type) when is_atom(Type)    -> throw({bad_type, Type});
hello_failed(Type) when is_integer(Type) -> throw({bad_value, Type}).

bad_request(bad_version)                -> ?OFPBRC_BAD_VERSION;
bad_request(?OFPBRC_BAD_VERSION)        -> bad_version;
bad_request(bad_type)                   -> ?OFPBRC_BAD_TYPE;
bad_request(?OFPBRC_BAD_TYPE)           -> bad_type;
bad_request(bad_stat)                   -> ?OFPBRC_BAD_STAT;
bad_request(?OFPBRC_BAD_STAT)           -> bad_stat;
bad_request(bad_experimenter)           -> ?OFPBRC_BAD_EXPERIMENTER;
bad_request(?OFPBRC_BAD_EXPERIMENTER)   -> bad_experimenter;
bad_request(bad_exp_type)               -> ?OFPBRC_BAD_EXP_TYPE;
bad_request(?OFPBRC_BAD_EXP_TYPE)       -> bad_exp_type;
bad_request(eperm)                      -> ?OFPBRC_EPERM;
bad_request(?OFPBRC_EPERM)              -> eperm;
bad_request(bad_len)                    -> ?OFPBRC_BAD_LEN;
bad_request(?OFPBRC_BAD_LEN)            -> bad_len;
bad_request(buffer_empty)               -> ?OFPBRC_BUFFER_EMPTY;
bad_request(?OFPBRC_BUFFER_EMPTY)       -> buffer_empty;
bad_request(buffer_unknown)             -> ?OFPBRC_BUFFER_UNKNOWN;
bad_request(?OFPBRC_BUFFER_UNKNOWN)     -> buffer_unknown;
bad_request(bad_table_id)               -> ?OFPBRC_BAD_TABLE_ID;
bad_request(?OFPBRC_BAD_TABLE_ID)       -> bad_table_id;
bad_request(is_slave)                   -> ?OFPBRC_IS_SLAVE;
bad_request(?OFPBRC_IS_SLAVE)           -> is_slave;
bad_request(bad_port)                   -> ?OFPBRC_BAD_PORT;
bad_request(?OFPBRC_BAD_PORT)           -> bad_port;
bad_request(bad_packet)                 -> ?OFPBRC_BAD_PACKET;
bad_request(?OFPBRC_BAD_PACKET)         -> bad_packet;
bad_request(Type) when is_atom(Type)    -> throw({bad_type, Type});
bad_request(Type) when is_integer(Type) -> throw({bad_value, Type}).

bad_action(bad_type)                   -> ?OFPBAC_BAD_TYPE;
bad_action(?OFPBAC_BAD_TYPE)           -> bad_type;
bad_action(bad_len)                    -> ?OFPBAC_BAD_LEN;
bad_action(?OFPBAC_BAD_LEN)            -> bad_len;
bad_action(bad_experimenter)           -> ?OFPBAC_BAD_EXPERIMENTER;
bad_action(?OFPBAC_BAD_EXPERIMENTER)   -> bad_experimenter;
bad_action(bad_exp_type)               -> ?OFPBAC_BAD_EXP_TYPE;
bad_action(?OFPBAC_BAD_EXP_TYPE)       -> bad_exp_type;
bad_action(bad_out_port)               -> ?OFPBAC_BAD_OUT_PORT;
bad_action(?OFPBAC_BAD_OUT_PORT)       -> bad_out_port;
bad_action(bad_argument)               -> ?OFPBAC_BAD_ARGUMENT;
bad_action(?OFPBAC_BAD_ARGUMENT)       -> bad_argument;
bad_action(eperm)                      -> ?OFPBAC_EPERM;
bad_action(?OFPBAC_EPERM)              -> eperm;
bad_action(too_many)                   -> ?OFPBAC_TOO_MANY;
bad_action(?OFPBAC_TOO_MANY)           -> too_many;
bad_action(bad_queue)                  -> ?OFPBAC_BAD_QUEUE;
bad_action(?OFPBAC_BAD_QUEUE)          -> bad_queue;
bad_action(bad_out_group)              -> ?OFPBAC_BAD_OUT_GROUP;
bad_action(?OFPBAC_BAD_OUT_GROUP)      -> bad_out_group;
bad_action(match_inconsistent)         -> ?OFPBAC_MATCH_INCONSISTENT;
bad_action(?OFPBAC_MATCH_INCONSISTENT) -> match_inconsistent;
bad_action(unsupported_order)          -> ?OFPBAC_UNSUPPORTED_ORDER;
bad_action(?OFPBAC_UNSUPPORTED_ORDER)  -> unsupported_order;
bad_action(bad_tag)                    -> ?OFPBAC_BAD_TAG;
bad_action(?OFPBAC_BAD_TAG)            -> bad_tag;
bad_action(bad_set_type)               -> ?OFPBAC_BAD_SET_TYPE;
bad_action(?OFPBAC_BAD_SET_TYPE)       -> bad_set_type;
bad_action(bad_set_len)                -> ?OFPBAC_BAD_SET_LEN;
bad_action(?OFPBAC_BAD_SET_LEN)        -> bad_set_len;
bad_action(bad_set_argument)           -> ?OFPBAC_BAD_SET_ARGUMENT;
bad_action(?OFPBAC_BAD_SET_ARGUMENT)   -> bad_set_argument;
bad_action(Type) when is_atom(Type)    -> throw({bad_type, Type});
bad_action(Type) when is_integer(Type) -> throw({bad_value, Type}).

bad_instruction(unknown_inst)                -> ?OFPBIC_UNKNOWN_INST;
bad_instruction(?OFPBIC_UNKNOWN_INST)        -> unknown_inst;
bad_instruction(unsup_inst)                  -> ?OFPBIC_UNSUP_INST;
bad_instruction(?OFPBIC_UNSUP_INST)          -> unsup_inst;
bad_instruction(bad_table_id)                -> ?OFPBIC_BAD_TABLE_ID;
bad_instruction(?OFPBIC_BAD_TABLE_ID)        -> bad_table_id;
bad_instruction(unsup_metadata)              -> ?OFPBIC_UNSUP_METADATA;
bad_instruction(?OFPBIC_UNSUP_METADATA)      -> unsup_metadata;
bad_instruction(unsup_metadata_mask)         -> ?OFPBIC_UNSUP_METADATA_MASK;
bad_instruction(?OFPBIC_UNSUP_METADATA_MASK) -> unsup_metadata_mask;
bad_instruction(bad_experimenter)            -> ?OFPBIC_BAD_EXPERIMENTER;
bad_instruction(?OFPBIC_BAD_EXPERIMENTER)    -> bad_experimenter;
bad_instruction(bad_exp_type)                -> ?OFPBIC_BAD_EXP_TYPE;
bad_instruction(?OFPBIC_BAD_EXP_TYPE)        -> bad_exp_type;
bad_instruction(bad_len)                     -> ?OFPBIC_BAD_LEN;
bad_instruction(?OFPBIC_BAD_LEN)             -> bad_len;
bad_instruction(eperm)                       -> ?OFPBIC_EPERM;
bad_instruction(?OFPBIC_EPERM)               -> eperm;
bad_instruction(Type) when is_atom(Type)     -> throw({bad_type, Type});
bad_instruction(Type) when is_integer(Type)  -> throw({bad_value, Type}).

bad_match(bad_type)                   -> ?OFPBMC_BAD_TYPE;
bad_match(?OFPBMC_BAD_TYPE)           -> bad_type;
bad_match(bad_len)                    -> ?OFPBMC_BAD_LEN;
bad_match(?OFPBMC_BAD_LEN)            -> bad_len;
bad_match(bad_tag)                    -> ?OFPBMC_BAD_TAG;
bad_match(?OFPBMC_BAD_TAG)            -> bad_tag;
bad_match(bad_dl_addr_mask)           -> ?OFPBMC_BAD_DL_ADDR_MASK;
bad_match(?OFPBMC_BAD_DL_ADDR_MASK)   -> bad_dl_addr_mask;
bad_match(bad_nw_addr_mask)           -> ?OFPBMC_BAD_NW_ADDR_MASK;
bad_match(?OFPBMC_BAD_NW_ADDR_MASK)   -> bad_nw_addr_mask;
bad_match(bad_wildcards)              -> ?OFPBMC_BAD_WILDCARDS;
bad_match(?OFPBMC_BAD_WILDCARDS)      -> bad_wildcards;
bad_match(bad_field)                  -> ?OFPBMC_BAD_FIELD;
bad_match(?OFPBMC_BAD_FIELD)          -> bad_field;
bad_match(bad_value)                  -> ?OFPBMC_BAD_VALUE;
bad_match(?OFPBMC_BAD_VALUE)          -> bad_value;
bad_match(bad_mask)                   -> ?OFPBMC_BAD_MASK;
bad_match(?OFPBMC_BAD_MASK)           -> bad_mask;
bad_match(bad_prereq)                 -> ?OFPBMC_BAD_PREREQ;
bad_match(?OFPBMC_BAD_PREREQ)         -> bad_prereq;
bad_match(dup_field)                  -> ?OFPBMC_DUP_FIELD;
bad_match(?OFPBMC_DUP_FIELD)          -> dup_field;
bad_match(eperm)                      -> ?OFPBMC_EPERM;
bad_match(?OFPBMC_EPERM)              -> eperm;
bad_match(Type) when is_atom(Type)    -> throw({bad_type, Type});
bad_match(Type) when is_integer(Type) -> throw({bad_value, Type}).

flow_mod_failed(unknown)                    -> ?OFPFMFC_UNKNOWN;
flow_mod_failed(?OFPFMFC_UNKNOWN)           -> unknown;
flow_mod_failed(table_full)                 -> ?OFPFMFC_TABLE_FULL;
flow_mod_failed(?OFPFMFC_TABLE_FULL)        -> table_full;
flow_mod_failed(bad_table_id)               -> ?OFPFMFC_BAD_TABLE_ID;
flow_mod_failed(?OFPFMFC_BAD_TABLE_ID)      -> bad_table_id;
flow_mod_failed(overlap)                    -> ?OFPFMFC_OVERLAP;
flow_mod_failed(?OFPFMFC_OVERLAP)           -> overlap;
flow_mod_failed(eperm)                      -> ?OFPFMFC_EPERM;
flow_mod_failed(?OFPFMFC_EPERM)             -> eperm;
flow_mod_failed(bad_timeout)                -> ?OFPFMFC_BAD_TIMEOUT;
flow_mod_failed(?OFPFMFC_BAD_TIMEOUT)       -> bad_timeout;
flow_mod_failed(bad_command)                -> ?OFPFMFC_BAD_COMMAND;
flow_mod_failed(?OFPFMFC_BAD_COMMAND)       -> bad_command;
flow_mod_failed(bad_flags)                  -> ?OFPFMFC_BAD_FLAGS;
flow_mod_failed(?OFPFMFC_BAD_FLAGS)         -> bad_flags;
flow_mod_failed(Type) when is_atom(Type)    -> throw({bad_type, Type});
flow_mod_failed(Type) when is_integer(Type) -> throw({bad_value, Type}).

group_mod_failed(group_exists)                  -> ?OFPGMFC_GROUP_EXISTS;
group_mod_failed(?OFPGMFC_GROUP_EXISTS)         -> group_exists;
group_mod_failed(invalid_group)                 -> ?OFPGMFC_INVALID_GROUP;
group_mod_failed(?OFPGMFC_INVALID_GROUP)        -> invalid_group;
group_mod_failed(weight_unsupported)            -> ?OFPGMFC_WEIGHT_UNSUPPORTED;
group_mod_failed(?OFPGMFC_WEIGHT_UNSUPPORTED)   -> weight_unsupported;
group_mod_failed(out_of_groups)                 -> ?OFPGMFC_OUT_OF_GROUPS;
group_mod_failed(?OFPGMFC_OUT_OF_GROUPS)        -> out_of_groups;
group_mod_failed(out_of_buckets)                -> ?OFPGMFC_OUT_OF_BUCKETS;
group_mod_failed(?OFPGMFC_OUT_OF_BUCKETS)       -> out_of_buckets;
group_mod_failed(chaining_unsupported)          -> ?OFPGMFC_CHAINING_UNSUPPORTED;
group_mod_failed(?OFPGMFC_CHAINING_UNSUPPORTED) -> chaining_unsupported;
group_mod_failed(watch_unsupported)             -> ?OFPGMFC_WATCH_UNSUPPORTED;
group_mod_failed(?OFPGMFC_WATCH_UNSUPPORTED)    -> watch_unsupported;
group_mod_failed(loop)                          -> ?OFPGMFC_LOOP;
group_mod_failed(?OFPGMFC_LOOP)                 -> loop;
group_mod_failed(unknown_group)                 -> ?OFPGMFC_UNKNOWN_GROUP;
group_mod_failed(?OFPGMFC_UNKNOWN_GROUP)        -> unknown_group;
group_mod_failed(chained_group)                 -> ?OFPGMFC_CHAINED_GROUP;
group_mod_failed(?OFPGMFC_CHAINED_GROUP)        -> chained_group;
group_mod_failed(bad_type)                      -> ?OFPGMFC_BAD_TYPE;
group_mod_failed(?OFPGMFC_BAD_TYPE)             -> bad_type;
group_mod_failed(bad_command)                   -> ?OFPGMFC_BAD_COMMAND;
group_mod_failed(?OFPGMFC_BAD_COMMAND)          -> bad_command;
group_mod_failed(bad_bucket)                    -> ?OFPGMFC_BAD_BUCKET;
group_mod_failed(?OFPGMFC_BAD_BUCKET)           -> bad_bucket;
group_mod_failed(bad_watch)                     -> ?OFPGMFC_BAD_WATCH;
group_mod_failed(?OFPGMFC_BAD_WATCH)            -> bad_watch;
group_mod_failed(eperm)                         -> ?OFPGMFC_EPERM;
group_mod_failed(?OFPGMFC_EPERM)                -> eperm;
group_mod_failed(Type) when is_atom(Type)       -> throw({bad_type, Type});
group_mod_failed(Type) when is_integer(Type)    -> throw({bad_value, Type}).

port_mod_failed(bad_port)                   -> ?OFPPMFC_BAD_PORT;
port_mod_failed(?OFPPMFC_BAD_PORT)          -> bad_port;
port_mod_failed(bad_hw_addr)                -> ?OFPPMFC_BAD_HW_ADDR;
port_mod_failed(?OFPPMFC_BAD_HW_ADDR)       -> bad_hw_addr;
port_mod_failed(bad_config)                 -> ?OFPPMFC_BAD_CONFIG;
port_mod_failed(?OFPPMFC_BAD_CONFIG)        -> bad_config;
port_mod_failed(bad_advertise)              -> ?OFPPMFC_BAD_ADVERTISE;
port_mod_failed(?OFPPMFC_BAD_ADVERTISE)     -> bad_advertise;
port_mod_failed(eperm)                      -> ?OFPPMFC_EPERM;
port_mod_failed(?OFPPMFC_EPERM)             -> eperm;
port_mod_failed(Type) when is_atom(Type)    -> throw({bad_type, Type});
port_mod_failed(Type) when is_integer(Type) -> throw({bad_value, Type}).

table_mod_failed(bad_table)                  -> ?OFPTMFC_BAD_TABLE;
table_mod_failed(?OFPTMFC_BAD_TABLE)         -> bad_table;
table_mod_failed(bad_config)                 -> ?OFPTMFC_BAD_CONFIG;
table_mod_failed(?OFPTMFC_BAD_CONFIG)        -> bad_config;
table_mod_failed(eperm)                      -> ?OFPTMFC_EPERM;
table_mod_failed(?OFPTMFC_EPERM)             -> eperm;
table_mod_failed(Type) when is_atom(Type)    -> throw({bad_type, Type});
table_mod_failed(Type) when is_integer(Type) -> throw({bad_value, Type}).

queue_op_failed(bad_port)                   -> ?OFPQOFC_BAD_PORT;
queue_op_failed(?OFPQOFC_BAD_PORT)          -> bad_port;
queue_op_failed(bad_queue)                  -> ?OFPQOFC_BAD_QUEUE;
queue_op_failed(?OFPQOFC_BAD_QUEUE)         -> bad_queue;
queue_op_failed(eperm)                      -> ?OFPQOFC_EPERM;
queue_op_failed(?OFPQOFC_EPERM)             -> eperm;
queue_op_failed(Type) when is_atom(Type)    -> throw({bad_type, Type});
queue_op_failed(Type) when is_integer(Type) -> throw({bad_value, Type}).

switch_config_failed(bad_flags)                  -> ?OFPSCFC_BAD_FLAGS;
switch_config_failed(?OFPSCFC_BAD_FLAGS)         -> bad_flags;
switch_config_failed(bad_len)                    -> ?OFPSCFC_BAD_LEN;
switch_config_failed(?OFPSCFC_BAD_LEN)           -> bad_len;
switch_config_failed(eperm)                      -> ?OFPSCFC_EPERM;
switch_config_failed(?OFPSCFC_EPERM)             -> eperm;
switch_config_failed(Type) when is_atom(Type)    -> throw({bad_type, Type});
switch_config_failed(Type) when is_integer(Type) -> throw({bad_value, Type}).

role_request_failed(stale)                      -> ?OFPRRFC_STALE;
role_request_failed(?OFPRRFC_STALE)             -> stale;
role_request_failed(unsup)                      -> ?OFPRRFC_UNSUP;
role_request_failed(?OFPRRFC_UNSUP)             -> unsup;
role_request_failed(bad_role)                   -> ?OFPRRFC_BAD_ROLE;
role_request_failed(?OFPRRFC_BAD_ROLE)          -> bad_role;
role_request_failed(Type) when is_atom(Type)    -> throw({bad_type, Type});
role_request_failed(Type) when is_integer(Type) -> throw({bad_value, Type}).

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
capability(port_blocked)               -> ?OFPC_PORT_BLOCKED;
capability(?OFPC_PORT_BLOCKED)         -> port_blocked;
capability(Type) when is_atom(Type)    -> throw({bad_type, Type});
capability(Type) when is_integer(Type) -> throw({bad_value, Type}).

configuration(frag_drop)                       -> ?OFPC_FRAG_DROP;
configuration(?OFPC_FRAG_DROP)                 -> frag_drop;
configuration(frag_reasm)                      -> ?OFPC_FRAG_REASM;
configuration(?OFPC_FRAG_REASM)                -> frag_reasm;
configuration(invalid_ttl_to_controller)       -> ?OFPC_INVALID_TTL_TO_CONTROLLER;
configuration(?OFPC_INVALID_TTL_TO_CONTROLLER) -> invalid_ttl_to_controller;
configuration(frag_mask)                       -> ?OFPC_FRAG_MASK;
configuration(?OFPC_FRAG_MASK)                 -> frag_mask;
configuration(Type) when is_atom(Type)         -> throw({bad_type, Type});
configuration(Type) when is_integer(Type)      -> throw({bad_value, Type}).

reason(no_match)                   -> ?OFPR_NO_MATCH;
reason(?OFPR_NO_MATCH)             -> no_match;
reason(action)                     -> ?OFPR_ACTION;
reason(?OFPR_ACTION)               -> action;
reason(invalid_ttl)                -> ?OFPR_INVALID_TTL;
reason(?OFPR_INVALID_TTL)          -> invalid_ttl;
reason(Type) when is_atom(Type)    -> throw({bad_type, Type});
reason(Type) when is_integer(Type) -> throw({bad_value, Type}).

removed_reason(idle_timeout)               -> ?OFPRR_IDLE_TIMEOUT;
removed_reason(?OFPRR_IDLE_TIMEOUT)        -> idle_timeout;
removed_reason(hard_timeout)               -> ?OFPRR_HARD_TIMEOUT;
removed_reason(?OFPRR_HARD_TIMEOUT)        -> hard_timeout;
removed_reason(delete)                     -> ?OFPRR_DELETE;
removed_reason(?OFPRR_DELETE)              -> delete;
removed_reason(group_delete)               -> ?OFPRR_GROUP_DELETE;
removed_reason(?OFPRR_GROUP_DELETE)        -> group_delete;
removed_reason(Type) when is_atom(Type)    -> throw({bad_type, Type});
removed_reason(Type) when is_integer(Type) -> throw({bad_value, Type}).

port_reason(add)                        -> ?OFPPR_ADD;
port_reason(?OFPPR_ADD)                 -> add;
port_reason(delete)                     -> ?OFPPR_DELETE;
port_reason(?OFPPR_DELETE)              -> delete;
port_reason(modify)                     -> ?OFPPR_MODIFY;
port_reason(?OFPPR_MODIFY)              -> modify;
port_reason(Type) when is_atom(Type)    -> throw({bad_type, Type});
port_reason(Type) when is_integer(Type) -> throw({bad_value, Type}).

match_type(standard)                   -> ?OFPMT_STANDARD;
match_type(?OFPMT_STANDARD)            -> standard;
match_type(oxm)                        -> ?OFPMT_OXM;
match_type(?OFPMT_OXM)                 -> oxm;
match_type(Type) when is_atom(Type)    -> throw({bad_type, Type});
match_type(Type) when is_integer(Type) -> throw({bad_value, Type}).

oxm_class(nxm_0)                      -> ?OFPXMC_NXM_0;
oxm_class(?OFPXMC_NXM_0)              -> nxm_0;
oxm_class(nxm_1)                      -> ?OFPXMC_NXM_1;
oxm_class(?OFPXMC_NXM_1)              -> nxm_1;
oxm_class(openflow_basic)             -> ?OFPXMC_OPENFLOW_BASIC;
oxm_class(?OFPXMC_OPENFLOW_BASIC)     -> openflow_basic;
oxm_class(experimenter)               -> ?OFPXMC_EXPERIMENTER;
oxm_class(?OFPXMC_EXPERIMENTER)       -> experimenter;
oxm_class(Type) when is_atom(Type)    -> throw({bad_type, Type});
oxm_class(Type) when is_integer(Type) -> throw({bad_value, Type}).

oxm_field(openflow_basic, Field)           -> oxm_field(Field);
oxm_field(_, not_used)                     -> 0;
oxm_field(_, 0)                            -> not_used;
oxm_field(_, Field) when is_atom(Field)    -> throw({bad_type, Field});
oxm_field(_, Field) when is_integer(Field) -> throw({bad_value, Field}).

oxm_field(in_port)                    -> ?OFPXMT_OFB_IN_PORT;
oxm_field(?OFPXMT_OFB_IN_PORT)        -> in_port;
oxm_field(in_phy_port)                -> ?OFPXMT_OFB_IN_PHY_PORT;
oxm_field(?OFPXMT_OFB_IN_PHY_PORT)    -> in_phy_port;
oxm_field(metadata)                   -> ?OFPXMT_OFB_METADATA;
oxm_field(?OFPXMT_OFB_METADATA)       -> metadata;
oxm_field(eth_dst)                    -> ?OFPXMT_OFB_ETH_DST;
oxm_field(?OFPXMT_OFB_ETH_DST)        -> eth_dst;
oxm_field(eth_src)                    -> ?OFPXMT_OFB_ETH_SRC;
oxm_field(?OFPXMT_OFB_ETH_SRC)        -> eth_src;
oxm_field(eth_type)                   -> ?OFPXMT_OFB_ETH_TYPE;
oxm_field(?OFPXMT_OFB_ETH_TYPE)       -> eth_type;
oxm_field(vlan_vid)                   -> ?OFPXMT_OFB_VLAN_VID;
oxm_field(?OFPXMT_OFB_VLAN_VID)       -> vlan_vid;
oxm_field(vlan_pcp)                   -> ?OFPXMT_OFB_VLAN_PCP;
oxm_field(?OFPXMT_OFB_VLAN_PCP)       -> vlan_pcp;
oxm_field(ip_dscp)                    -> ?OFPXMT_OFB_IP_DSCP;
oxm_field(?OFPXMT_OFB_IP_DSCP)        -> ip_dscp;
oxm_field(ip_ecn)                     -> ?OFPXMT_OFB_IP_ECN;
oxm_field(?OFPXMT_OFB_IP_ECN)         -> ip_ecn;
oxm_field(ip_proto)                   -> ?OFPXMT_OFB_IP_PROTO;
oxm_field(?OFPXMT_OFB_IP_PROTO)       -> ip_proto;
oxm_field(ipv4_src)                   -> ?OFPXMT_OFB_IPV4_SRC;
oxm_field(?OFPXMT_OFB_IPV4_SRC)       -> ipv4_src;
oxm_field(ipv4_dst)                   -> ?OFPXMT_OFB_IPV4_DST;
oxm_field(?OFPXMT_OFB_IPV4_DST)       -> ipv4_dst;
oxm_field(tcp_src)                    -> ?OFPXMT_OFB_TCP_SRC;
oxm_field(?OFPXMT_OFB_TCP_SRC)        -> tcp_src;
oxm_field(tcp_dst)                    -> ?OFPXMT_OFB_TCP_DST;
oxm_field(?OFPXMT_OFB_TCP_DST)        -> tcp_dst;
oxm_field(udp_src)                    -> ?OFPXMT_OFB_UDP_SRC;
oxm_field(?OFPXMT_OFB_UDP_SRC)        -> udp_src;
oxm_field(udp_dst)                    -> ?OFPXMT_OFB_UDP_DST;
oxm_field(?OFPXMT_OFB_UDP_DST)        -> udp_dst;
oxm_field(sctp_src)                   -> ?OFPXMT_OFB_SCTP_SRC;
oxm_field(?OFPXMT_OFB_SCTP_SRC)       -> sctp_src;
oxm_field(sctp_dst)                   -> ?OFPXMT_OFB_SCTP_DST;
oxm_field(?OFPXMT_OFB_SCTP_DST)       -> sctp_dst;
oxm_field(icmpv4_type)                -> ?OFPXMT_OFB_ICMPV4_TYPE;
oxm_field(?OFPXMT_OFB_ICMPV4_TYPE)    -> icmpv4_type;
oxm_field(icmpv4_code)                -> ?OFPXMT_OFB_ICMPV4_CODE;
oxm_field(?OFPXMT_OFB_ICMPV4_CODE)    -> icmpv4_code;
oxm_field(arp_op)                     -> ?OFPXMT_OFB_ARP_OP;
oxm_field(?OFPXMT_OFB_ARP_OP)         -> arp_op;
oxm_field(arp_spa)                    -> ?OFPXMT_OFB_ARP_SPA;
oxm_field(?OFPXMT_OFB_ARP_SPA)        -> arp_spa;
oxm_field(arp_tpa)                    -> ?OFPXMT_OFB_ARP_TPA;
oxm_field(?OFPXMT_OFB_ARP_TPA)        -> arp_tpa;
oxm_field(arp_sha)                    -> ?OFPXMT_OFB_ARP_SHA;
oxm_field(?OFPXMT_OFB_ARP_SHA)        -> arp_sha;
oxm_field(arp_tha)                    -> ?OFPXMT_OFB_ARP_THA;
oxm_field(?OFPXMT_OFB_ARP_THA)        -> arp_tha;
oxm_field(ipv6_src)                   -> ?OFPXMT_OFB_IPV6_SRC;
oxm_field(?OFPXMT_OFB_IPV6_SRC)       -> ipv6_src;
oxm_field(ipv6_dst)                   -> ?OFPXMT_OFB_IPV6_DST;
oxm_field(?OFPXMT_OFB_IPV6_DST)       -> ipv6_dst;
oxm_field(ipv6_flabel)                -> ?OFPXMT_OFB_IPV6_FLABEL;
oxm_field(?OFPXMT_OFB_IPV6_FLABEL)    -> ipv6_flabel;
oxm_field(icmpv6_type)                -> ?OFPXMT_OFB_ICMPV6_TYPE;
oxm_field(?OFPXMT_OFB_ICMPV6_TYPE)    -> icmpv6_type;
oxm_field(icmpv6_code)                -> ?OFPXMT_OFB_ICMPV6_CODE;
oxm_field(?OFPXMT_OFB_ICMPV6_CODE)    -> icmpv6_code;
oxm_field(ipv6_nd_target)             -> ?OFPXMT_OFB_IPV6_ND_TARGET;
oxm_field(?OFPXMT_OFB_IPV6_ND_TARGET) -> ipv6_nd_target;
oxm_field(ipv6_nd_sll)                -> ?OFPXMT_OFB_IPV6_ND_SLL;
oxm_field(?OFPXMT_OFB_IPV6_ND_SLL)    -> ipv6_nd_sll;
oxm_field(ipv6_nd_tll)                -> ?OFPXMT_OFB_IPV6_ND_TLL;
oxm_field(?OFPXMT_OFB_IPV6_ND_TLL)    -> ipv6_nd_tll;
oxm_field(mpls_label)                 -> ?OFPXMT_OFB_MPLS_LABEL;
oxm_field(?OFPXMT_OFB_MPLS_LABEL)     -> mpls_label;
oxm_field(mpls_tc)                    -> ?OFPXMT_OFB_MPLS_TC;
oxm_field(?OFPXMT_OFB_MPLS_TC)        -> mpls_tc;
oxm_field(Type) when is_atom(Type)    -> throw({bad_type, Type});
oxm_field(Type) when is_integer(Type) -> throw({bad_value, Type}).

action_type(output)                     -> ?OFPAT_OUTPUT;
action_type(?OFPAT_OUTPUT)              -> output;
action_type(copy_ttl_out)               -> ?OFPAT_COPY_TTL_OUT;
action_type(?OFPAT_COPY_TTL_OUT)        -> copy_ttl_out;
action_type(copy_ttl_in)                -> ?OFPAT_COPY_TTL_IN;
action_type(?OFPAT_COPY_TTL_IN)         -> copy_ttl_in;
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
action_type(set_field)                  -> ?OFPAT_SET_FIELD;
action_type(?OFPAT_SET_FIELD)           -> set_field;
action_type(experimenter)               -> ?OFPAT_EXPERIMENTER;
action_type(?OFPAT_EXPERIMENTER)        -> experimenter;
action_type(?OFPAT_EXPERIMENTER_BIT)    -> experimenter;
action_type(Type) when is_atom(Type)    -> throw({bad_type, Type});
action_type(Type) when is_integer(Type) -> throw({bad_value, Type}).

table_config(continue)                   -> ?OFPTC_TABLE_MISS_CONTINUE;
table_config(?OFPTC_TABLE_MISS_CONTINUE) -> continue;
table_config(drop)                       -> ?OFPTC_TABLE_MISS_DROP;
table_config(?OFPTC_TABLE_MISS_DROP)     -> drop;
table_config(mask)                       -> ?OFPTC_TABLE_MISS_MASK;
table_config(?OFPTC_TABLE_MISS_MASK)     -> mask;
table_config(Type) when is_atom(Type)    -> throw({bad_type, Type});
table_config(Type) when is_integer(Type) -> throw({bad_value, Type}).

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
flow_flag(reset_counts)               -> ?OFPFF_RESET_COUNTS;
flow_flag(?OFPFF_RESET_COUNTS)        -> reset_counts;
flow_flag(Type) when is_atom(Type)    -> throw({bad_type, Type});
flow_flag(Type) when is_integer(Type) -> throw({bad_value, Type}).

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

group_command(add)                        -> ?OFPGC_ADD;
group_command(?OFPGC_ADD)                 -> add;
group_command(modify)                     -> ?OFPGC_MODIFY;
group_command(?OFPGC_MODIFY)              -> modify;
group_command(delete)                     -> ?OFPGC_DELETE;
group_command(?OFPGC_DELETE)              -> delete;
group_command(Type) when is_atom(Type)    -> throw({bad_type, Type});
group_command(Type) when is_integer(Type) -> throw({bad_value, Type}).

group_type(all)                        -> ?OFPGT_ALL;
group_type(?OFPGT_ALL)                 -> all;
group_type(select)                     -> ?OFPGT_SELECT;
group_type(?OFPGT_SELECT)              -> select;
group_type(indirect)                   -> ?OFPGT_INDIRECT;
group_type(?OFPGT_INDIRECT)            -> indirect;
group_type(ff)                         -> ?OFPGT_FF;
group_type(?OFPGT_FF)                  -> ff;
group_type(Type) when is_atom(Type)    -> throw({bad_type, Type});
group_type(Type) when is_integer(Type) -> throw({bad_value, Type}).

controller_role(nochange)                   -> ?OFPCR_ROLE_NOCHANGE;
controller_role(?OFPCR_ROLE_NOCHANGE)       -> nochange;
controller_role(equal)                      -> ?OFPCR_ROLE_EQUAL;
controller_role(?OFPCR_ROLE_EQUAL)          -> equal;
controller_role(master)                     -> ?OFPCR_ROLE_MASTER;
controller_role(?OFPCR_ROLE_MASTER)         -> master;
controller_role(slave)                      -> ?OFPCR_ROLE_SLAVE;
controller_role(?OFPCR_ROLE_SLAVE)          -> slave;
controller_role(Type) when is_atom(Type)    -> throw({bad_type, Type});
controller_role(Type) when is_integer(Type) -> throw({bad_value, Type}).

queue_property(min_rate)                   -> ?OFPQT_MIN_RATE;
queue_property(?OFPQT_MIN_RATE)            -> min_rate;
queue_property(max_rate)                   -> ?OFPQT_MAX_RATE;
queue_property(?OFPQT_MAX_RATE)            -> max_rate;
queue_property(experimenter)               -> ?OFPQT_EXPERIMENTER;
queue_property(?OFPQT_EXPERIMENTER)        -> experimenter;
queue_property(Type) when is_integer(Type) -> throw({bad_value, Type}).

stats_type(desc)                       -> ?OFPST_DESC;
stats_type(?OFPST_DESC)                -> desc;
stats_type(flow)                       -> ?OFPST_FLOW;
stats_type(?OFPST_FLOW)                -> flow;
stats_type(aggregate)                  -> ?OFPST_AGGREGATE;
stats_type(?OFPST_AGGREGATE)           -> aggregate;
stats_type(table)                      -> ?OFPST_TABLE;
stats_type(?OFPST_TABLE)               -> table;
stats_type(port)                       -> ?OFPST_PORT;
stats_type(?OFPST_PORT)                -> port;
stats_type(queue)                      -> ?OFPST_QUEUE;
stats_type(?OFPST_QUEUE)               -> queue;
stats_type(group)                      -> ?OFPST_GROUP;
stats_type(?OFPST_GROUP)               -> group;
stats_type(group_desc)                 -> ?OFPST_GROUP_DESC;
stats_type(?OFPST_GROUP_DESC)          -> group_desc;
stats_type(group_features)             -> ?OFPST_GROUP_FEATURES;
stats_type(?OFPST_GROUP_FEATURES)      -> group_features;
stats_type(experimenter)               -> ?OFPST_EXPERIMENTER;
stats_type(?OFPST_EXPERIMENTER)        -> experimenter;
stats_type(Type) when is_integer(Type) -> throw({bad_value, Type}).

stats_request_flag(Type) when is_atom(Type)    -> throw({bad_type, Type});
stats_request_flag(Type) when is_integer(Type) -> throw({bad_value, Type}).

stats_reply_flag(more)                       -> ?OFPSF_REPLY_MORE;
stats_reply_flag(?OFPSF_REPLY_MORE)          -> more;
stats_reply_flag(Type) when is_atom(Type)    -> throw({bad_type, Type});
stats_reply_flag(Type) when is_integer(Type) -> throw({bad_value, Type}).

group_capability(select_weight)              -> ?OFPGFC_SELECT_WEIGHT;
group_capability(?OFPGFC_SELECT_WEIGHT)      -> select_weight;
group_capability(select_liveness)            -> ?OFPGFC_SELECT_LIVENESS;
group_capability(?OFPGFC_SELECT_LIVENESS)    -> select_liveness;
group_capability(chaining)                   -> ?OFPGFC_CHAINING;
group_capability(?OFPGFC_CHAINING)           -> chaining;
group_capability(chaining_checks)            -> ?OFPGFC_CHAINING_CHECKS;
group_capability(?OFPGFC_CHAINING_CHECKS)    -> chaining_checks;
group_capability(Type) when is_atom(Type)    -> throw({bad_type, Type});
group_capability(Type) when is_integer(Type) -> throw({bad_value, Type}).

%%% Encoding/decoding IDs ------------------------------------------------------

encode_group_id(any)                      -> ?OFPG_ANY;
encode_group_id(all)                      -> ?OFPG_ALL;
encode_group_id(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_group_id(Int) when is_integer(Int) -> Int.

decode_group_id(?OFPG_ANY)                -> any;
decode_group_id(?OFPG_ALL)                -> all;
decode_group_id(Int) when is_integer(Int) -> Int.

encode_table_id(all)                      -> ?OFPTT_ALL;
encode_table_id(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_table_id(Int) when is_integer(Int) -> Int.

decode_table_id(?OFPTT_ALL)               -> all;
decode_table_id(Int) when is_integer(Int) -> Int.

encode_queue_id(all)                      -> ?OFPQ_ALL;
encode_queue_id(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_queue_id(Int) when is_integer(Int) -> Int.

decode_queue_id(?OFPQ_ALL)               -> all;
decode_queue_id(Int) when is_integer(Int) -> Int.

encode_buffer_id(no_buffer)                -> ?OFPCML_NO_BUFFER;
encode_buffer_id(Type) when is_atom(Type)  -> throw({bad_type, Type});
encode_buffer_id(Int) when is_integer(Int) -> Int.

decode_buffer_id(?OFPCML_NO_BUFFER)        -> no_buffer;
decode_buffer_id(Int) when is_integer(Int) -> Int.

encode_max_length(Value) ->
    encode_buffer_id(Value).

decode_max_length(Value) ->
    decode_buffer_id(Value).

%%%-----------------------------------------------------------------------------
%%% Helper functions
%%%-----------------------------------------------------------------------------

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

-spec get_experimenter_bit(atom()) -> integer().
get_experimenter_bit(instruction_type) ->
    ?OFPIT_EXPERIMENTER_BIT;
get_experimenter_bit(action_type) ->
    ?OFPAT_EXPERIMENTER_BIT.
