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
         filter_out_message/3,
         type_atom/1,
         add_aux_id/2,
         split_multipart/1]).

-include("of_protocol.hrl").
-include("ofp_v4.hrl").

%% @doc Create an error message.
-spec create_error(atom(), atom()) -> ofp_error_msg().
create_error(Type, Code) ->
    #ofp_error_msg{type = Type,
                   code = Code}.

%% @doc Create role change message.
-spec create_role(atom(), integer()) -> ofp_role_reply().
create_role(Role, GenId) ->
    #ofp_role_reply{role = Role,
                    generation_id = GenId}.

%% @doc Extract role change information.
-spec extract_role(ofp_role_request()) -> {atom(), integer()}.
extract_role(#ofp_role_request{role = Role,
                               generation_id = GenId}) ->
    {Role, GenId}.

%% @doc Create async filters message.
-spec create_async(#async_config{}) -> #ofp_get_async_reply{}.
create_async(#async_config{
                master_equal_packet_in = MEP,
                master_equal_port_status = MES,
                master_equal_flow_removed = MEF,
                slave_packet_in = SP,
                slave_port_status = SS,
                slave_flow_removed = SF}) ->
    #ofp_get_async_reply{packet_in_mask = {MEP, SP},
                         port_status_mask = {MES, SS},
                         flow_removed_mask = {MEF, SF}}.

%% @doc Extract async filters information.
-spec extract_async(#ofp_set_async{}) -> #async_config{}.
extract_async(#ofp_set_async{packet_in_mask = {MEP, SP},
                             port_status_mask = {MES, SS},
                             flow_removed_mask = {MEF, SF}}) ->
    #async_config{
       master_equal_packet_in = MEP,
       master_equal_port_status = MES,
       master_equal_flow_removed = MEF,
       slave_packet_in = SP,
       slave_port_status = SS,
       slave_flow_removed = SF
      }.

-spec filter_out_message(#ofp_message{},
                         master | slave | equal,
                         #async_config{}) -> boolean().
filter_out_message(#ofp_message{type = Type, body = Body}, Role, Filter) ->
    {PacketInFilter, PortStatusFilter, FlowRemovedFilter} =
        case Role of
            slave ->
                {Filter#async_config.slave_packet_in,
                 Filter#async_config.slave_port_status,
                 Filter#async_config.slave_flow_removed};
            _Else ->
                {Filter#async_config.master_equal_packet_in,
                 Filter#async_config.master_equal_port_status,
                 Filter#async_config.master_equal_flow_removed}
        end,
    case Type of
        packet_in ->
            Reason = Body#ofp_packet_in.reason,
            should_filter_out(Reason, PacketInFilter);
        port_status ->
            Reason = Body#ofp_port_status.reason,
            should_filter_out(Reason, PortStatusFilter);
        flow_removed ->
            Reason = Body#ofp_flow_removed.reason,
            should_filter_out(Reason, FlowRemovedFilter);
        _Other ->
            false
    end.

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

split_multipart(#ofp_message{body = #ofp_table_features_reply{}} = Message) ->
    Features = Message#ofp_message.body#ofp_table_features_reply.body,
    split_table_features(Message#ofp_message{body = []}, Features, []);
split_multipart(Message) ->
    [Message].

split_table_features(_Header, [], Messages) ->
    lists:reverse(Messages);
split_table_features(Header, Feats, Messages) ->
    {FirstTen, Rest} = split2(10, Feats),
    Flags = case Rest of
                [] ->
                    [];
                _Else ->
                    [more]
            end,
    TableFeatures = #ofp_table_features_reply{flags = Flags,
                                              body = FirstTen},
    NewMessage = Header#ofp_message{body = TableFeatures},
    split_table_features(Header, Rest, [NewMessage | Messages]).

split2(N, List) ->
    split2(N, List, []).

split2(0, Tail, Head) ->
    {lists:reverse(Head), Tail};
split2(_, [], Head) ->
    {lists:reverse(Head), []};
split2(N, [X | Tail], Head) ->
    split2(N - 1, Tail, [X | Head]).

should_filter_out(Reason, Filter) ->
    not lists:member(Reason, Filter).
