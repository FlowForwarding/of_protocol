%%%-----------------------------------------------------------------------------
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
%%------------------------------------------------------------------------------

%% @author Erlang Solutions Ltd. <openflow@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org
%% @doc Supervisor for listener waiting for connections initiated by OpenFlow
%% controllers.
-module(ofp_conn_listener_sup).

-behaviour(supervisor).

%% API
-export([start_link/4]).

%% Supervisor callbacks
-export([init/1]).

%%------------------------------------------------------------------------------
%% Internal API functions
%%------------------------------------------------------------------------------

%% @doc Starts the supervisor of listener for connections initiated by OpenFlow
%% controllers.
%%
%% `Address' specifies the ip address the server should listen on. `ChannelSup'
%% is the pid of the supervisor that will take care of ofp channels.
-spec start_link(Address :: inet:ip_address(), Port :: inet:port_number(),
                 ChannelSup :: pid(), ChannelOpts :: [term()]) ->
                        {ok, Pid :: pid()} |
                        {ok, undefined} |
                        {error, Reason :: term()}.
start_link(Address, Port, ChannelSup, ChannelOpts) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Address, Port, ChannelSup,
                                                      ChannelOpts]).

%%------------------------------------------------------------------------------
%% Supervisor callbacks
%%------------------------------------------------------------------------------

%% @private Initializes the supervisor.
init(Args) ->
    ConnListenerSpec =  {ofp_conn_listener,
                         {ofp_conn_listener, start_link, Args},
                         transient, 1000, worker, [ofp_conn_listener]},

    {ok, {{one_for_one, 5, 10}, [ConnListenerSpec]}}.
