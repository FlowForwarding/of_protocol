%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc Module for mapping between atoms and bits for OFP 1.1.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_v2_map).

%% Helper functions
%% -export([get_experimenter_bit/1]).

%% Mapping functions
-export([msg_type/1]).
-export([port_config/1,
         port_state/1,
         encode_port_no/1,
         decode_port_no/1,
         port_feature/1]).

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

%%%-----------------------------------------------------------------------------
%%% Helper functions
%%%-----------------------------------------------------------------------------

%% -spec get_experimenter_bit(atom()) -> integer().
%% get_experimenter_bit(instruction_type) ->
%%     ?OFPIT_EXPERIMENTER_BIT;
%% get_experimenter_bit(action_type) ->
%%     ?OFPAT_EXPERIMENTER_BIT.
