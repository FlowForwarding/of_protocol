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
-export([open/3,
         send/1,
         send/2,
         make_slaves/1]).

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

open(Host, Port, Opts) ->
    supervisor:start_child(ofp_channel_sup, [Host, Port, Opts]).

send(Message) ->
    [send(Pid, Message)
     || {_, Pid, _, _} <- supervisor:which_children(ofp_channel_sup)].

send(Pid, Message) ->
    ofp_client:send(Pid, Message).

make_slaves(Caller) ->
    [ofp_client:make_slave(Pid)
     || {_, Pid, _, _} <- supervisor:which_children(ofp_channel_sup),
        Pid /= Caller].
