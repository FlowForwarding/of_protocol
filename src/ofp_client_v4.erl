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
%% @doc OpenFlow v4 specific functions for the client.
-module(ofp_client_v4).

-export([create_error/2,
         create_role/2,
         extract_role/1,
         create_async/1,
         extract_async/1,
         type_atom/1,
         add_aux_id/2]).

-include("ofp_v4.hrl").

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

%% @doc Create async filters message.
-spec create_async({Masks, Masks}) -> record() when
      Masks :: {boolean(), boolean(), boolean()}.
create_async({{P1, S1, F1}, {P2, S2, F2}}) ->
    #ofp_get_async_reply{packet_in_mask = {P1, P2},
                         port_status_mask = {S1, S2},
                         flow_removed_mask = {F1, F2}}.

%% @doc Extract async filters information.
-spec extract_async(record()) -> {Masks, Masks} when
      Masks :: {boolean(), boolean(), boolean()}.
extract_async(#ofp_set_async{packet_in_mask = {P1, P2},
                             port_status_mask = {S1, S2},
                             flow_removed_mask = {F1, F2}}) ->
    {{P1, S1, F1}, {P2, S2, F2}}.

-spec type_atom(ofp_message_body()) -> integer().
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
type_atom(#ofp_desc_request{}) ->
    multipart_request;
type_atom(#ofp_desc_reply{}) ->
    multipart_reply;
type_atom(#ofp_flow_stats_request{}) ->
    multipart_request;
type_atom(#ofp_flow_stats_reply{}) ->
    multipart_reply;
type_atom(#ofp_aggregate_stats_request{}) ->
    multipart_request;
type_atom(#ofp_aggregate_stats_reply{}) ->
    multipart_reply;
type_atom(#ofp_table_stats_request{}) ->
    multipart_request;
type_atom(#ofp_table_stats_reply{}) ->
    multipart_reply;
type_atom(#ofp_table_features_request{}) ->
    multipart_request;
type_atom(#ofp_table_features_reply{}) ->
    multipart_reply;
type_atom(#ofp_port_stats_request{}) ->
    multipart_request;
type_atom(#ofp_port_stats_reply{}) ->
    multipart_reply;
type_atom(#ofp_port_desc_request{}) ->
    multipart_request;
type_atom(#ofp_port_desc_reply{}) ->
    multipart_reply;
type_atom(#ofp_queue_stats_request{}) ->
    multipart_request;
type_atom(#ofp_queue_stats_reply{}) ->
    multipart_reply;
type_atom(#ofp_group_stats_request{}) ->
    multipart_request;
type_atom(#ofp_group_stats_reply{}) ->
    multipart_reply;
type_atom(#ofp_group_desc_request{}) ->
    multipart_request;
type_atom(#ofp_group_desc_reply{}) ->
    multipart_reply;
type_atom(#ofp_group_features_request{}) ->
    multipart_request;
type_atom(#ofp_group_features_reply{}) ->
    multipart_reply;
type_atom(#ofp_meter_stats_request{}) ->
    multipart_request;
type_atom(#ofp_meter_stats_reply{}) ->
    multipart_reply;
type_atom(#ofp_meter_config_request{}) ->
    multipart_request;
type_atom(#ofp_meter_config_reply{}) ->
    multipart_reply;
type_atom(#ofp_meter_features_request{}) ->
    multipart_request;
type_atom(#ofp_meter_features_reply{}) ->
    multipart_reply;
type_atom(#ofp_experimenter_request{}) ->
    multipart_request;
type_atom(#ofp_experimenter_reply{}) ->
    multipart_reply;
type_atom(#ofp_barrier_request{}) ->
    barrier_request;
type_atom(#ofp_barrier_reply{}) ->
    barrier_reply;
type_atom(#ofp_queue_get_config_request{}) ->
    queue_get_config_request;
type_atom(#ofp_queue_get_config_reply{}) ->
    queue_get_config_reply;
type_atom(#ofp_role_request{}) ->
    role_request;
type_atom(#ofp_role_reply{}) ->
    role_reply;
type_atom(#ofp_get_async_request{}) ->
    get_async_request;
type_atom(#ofp_get_async_reply{}) ->
    get_async_reply;
type_atom(#ofp_set_async{}) ->
    set_async;
type_atom(#ofp_meter_mod{}) ->
    meter_mod.

add_aux_id(#ofp_features_reply{} = Reply, Id) ->
    Reply#ofp_features_reply{auxiliary_id = Id}.
