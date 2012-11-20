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
         extract_async/1]).

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
