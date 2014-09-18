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
-export([open/4,
         send/2,
         make_slaves/2,
         get_ets/1]).

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

%% @doc Opens the OpenFlow channel to the controller described by the
%% `ControllerHandle'.
%%
%% The channel can be opened in two ways: the switch may actively try to connect
%% to a controller or listen to a connection from a controller. In the first
%% scenario the `ControllerHandle' is a four element tuple tagged
%% with remote_peer. The second, third and fourth tuple's element are ip address
%% of the controller, the port it listens on and the protocol type respectively.
%% In the second scenario the `ControllerHandle' is a three element tuple
%% tagged with socket. The subsequent elements are the socket holding
%% the connection to the controller that initiated it and the protocol type.
-spec open(ChannelSupPid :: pid(), Id :: string(), ControllerHandle,
           Opts :: [term()]) -> StartChildRet :: term() when
      ControllerHandle ::
        {remote_peer, inet:ip_address(), inet:port_number(), Proto} |
        {socket, inet:socket(), Proto},
      Proto :: tcp | tls.
open(Pid, Id, ControllerHandle, Opts) ->
    supervisor:start_child(Pid, [Id, ControllerHandle, Opts]).

send(SwitchId, Message) when is_integer(SwitchId) ->
    Tid = get_ets(SwitchId),
%% Beware that the contents of the table can change mid flight, Pid may be gone,
%% send() may fail.
    lists:foreach(fun({main,Pid}) ->
         try
                % XXX quietly ignores errors returned by send.
                  send(Pid, Message)
         catch _:Error ->
                  io:format("Cannot send message to controller ~p: ~p\n", [Pid,Error]),
                  ignore
         end
    end, ets:lookup(Tid, main));
send(Pid, Message) when is_pid(Pid) ->
    ofp_client:send(Pid, Message).

make_slaves(Tid, Caller) ->
    [ofp_client:make_slave(Pid)
     || {main, Pid} <- ets:lookup(Tid, main), Pid /= Caller].

get_ets(SwitchId) ->
    list_to_atom("ofp_channel_" ++ integer_to_list(SwitchId)).
