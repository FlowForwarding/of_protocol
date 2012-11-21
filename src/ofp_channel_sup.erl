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
%% @doc Supervisor module for the clients connected to the controllers.
-module(ofp_channel_sup).

-behaviour(supervisor).

%% Internal API
-export([start_link/0,
         make_slaves/0]).

%% Supervisor callbacks
-export([init/1]).

%%------------------------------------------------------------------------------
%% Internal API functions
%%------------------------------------------------------------------------------

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

make_slaves() ->
    [ofp_client:make_slave(Pid)
     || {_, Pid, _, _} <- supervisor:which_children(?MODULE)].

%%------------------------------------------------------------------------------
%% Supervisor callbacks
%%------------------------------------------------------------------------------

init([]) ->
    ClientSpec = {ofp_client, {ofp_client, start_link, []},
                  transient, 1000, worker, [ofp_client]},
    {ok, {{simple_one_for_one, 5, 10}, [ClientSpec]}}.
