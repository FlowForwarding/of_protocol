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
%% @doc OpenFlow Channel API module.
-module(ofp_channel).

%% API
-export([open/5,
         send/2,
         make_slaves/2,
         get_ets/1]).

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

open(Pid, Id, Host, Port, Opts) ->
    supervisor:start_child(Pid, [Id, Host, Port, Opts]).

send(SwitchId, Message) when is_integer(SwitchId) ->
    Tid = get_ets(SwitchId),
    [send(Pid, Message) || {main, Pid} <- ets:lookup(Tid, main)];
send(Pid, Message) when is_pid(Pid) ->
    ofp_client:send(Pid, Message).

make_slaves(Tid, Caller) ->
    [ofp_client:make_slave(Pid)
     || {main, Pid} <- ets:lookup(Tid, main), Pid /= Caller].

get_ets(SwitchId) ->
    list_to_atom("ofp_channel_" ++ integer_to_list(SwitchId)).
