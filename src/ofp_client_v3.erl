%%------------------------------------------------------------------------------
%% Copyright 2012 FlowForwarding.org
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%-----------------------------------------------------------------------------

%% @author Erlang Solutions Ltd. <openflow@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org
%% @doc OpenFlow v3 specific functions for the client.
-module(ofp_client_v3).

-export([create_error/2,
         create_role/2,
         extract_role/1,
         type_atom/1]).

-include("ofp_v3.hrl").

%% @doc Create an error message.
-spec create_error(atom(), atom()) -> record().
create_error(Type, Code) ->
    #ofp_error_msg{type = Type,
                   code = Code}.

%% @doc Create role change message.
-spec create_role(atom(), integer()) -> record().
create_role(Role, GenId) ->
    #ofp_role_reply{role = Role,
                    generation_id = GenId}.

%% @doc Extract role change information.
-spec extract_role(record()) -> {atom(), integer()}.
extract_role(#ofp_role_request{role = Role,
                               generation_id = GenId}) ->
    {Role, GenId}.

-spec type_atom(ofp_message_body()) -> atom().
type_atom(#ofp_error_msg{}) ->
    error;
type_atom(#ofp_error_msg_experimenter{}) ->
    error;
type_atom(#ofp_echo_request{}) ->
    echo_request;
type_atom(#ofp_echo_reply{}) ->
    echo_reply;
type_atom(#ofp_experimenter{}) ->
    experimenter;
type_atom(#ofp_features_request{}) ->
    features_request;
type_atom(#ofp_features_reply{}) ->
    features_reply;
type_atom(#ofp_get_config_request{}) ->
    get_config_request;
type_atom(#ofp_get_config_reply{}) ->
    get_config_reply;
type_atom(#ofp_set_config{}) ->
    set_config;
type_atom(#ofp_packet_in{}) ->
    packet_in;
type_atom(#ofp_flow_removed{}) ->
    flow_removed;
type_atom(#ofp_port_status{}) ->
    port_status;
type_atom(#ofp_queue_get_config_request{}) ->
    queue_get_config_request;
type_atom(#ofp_queue_get_config_reply{}) ->
    queue_get_config_reply;
type_atom(#ofp_packet_out{}) ->
    packet_out;
type_atom(#ofp_flow_mod{}) ->
    flow_mod;
type_atom(#ofp_group_mod{}) ->
    group_mod;
type_atom(#ofp_port_mod{}) ->
    port_mod;
type_atom(#ofp_table_mod{}) ->
    table_mod;
type_atom(#ofp_desc_stats_request{}) ->
    stats_request;
type_atom(#ofp_desc_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_flow_stats_request{}) ->
    stats_request;
type_atom(#ofp_flow_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_aggregate_stats_request{}) ->
    stats_request;
type_atom(#ofp_aggregate_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_table_stats_request{}) ->
    stats_request;
type_atom(#ofp_table_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_port_stats_request{}) ->
    stats_request;
type_atom(#ofp_port_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_queue_stats_request{}) ->
    stats_request;
type_atom(#ofp_queue_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_group_stats_request{}) ->
    stats_request;
type_atom(#ofp_group_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_group_desc_stats_request{}) ->
    stats_request;
type_atom(#ofp_group_desc_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_group_features_stats_request{}) ->
    stats_request;
type_atom(#ofp_group_features_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_experimenter_stats_request{}) ->
    stats_request;
type_atom(#ofp_experimenter_stats_reply{}) ->
    stats_reply;
type_atom(#ofp_barrier_request{}) ->
    barrier_request;
type_atom(#ofp_barrier_reply{}) ->
    barrier_reply;
type_atom(#ofp_role_request{}) ->
    role_request;
type_atom(#ofp_role_reply{}) ->
    role_reply.
