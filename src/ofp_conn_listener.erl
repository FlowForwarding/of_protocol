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
%% @doc Listener for connections initiated by OpenFlow controllers.
-module(ofp_conn_listener).

-behaviour(gen_server).

%% API
-export([start_link/4,
        stop/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
          listen_socket = undefined :: inet:socket(),
          ofp_channel_sup = undefined :: pid(),
          ofp_channel_opts  = [] :: [term()]}).

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

%% @doc Starts the server.
%%
%% @see ofp_conn_listener_sup:start_link/4.
-spec start_link(Address :: inet:ip_address(), Port :: inet:port_number(),
                 ChannelSup :: pid(), ChannelOpts :: [term()]) ->
                        {ok, Pid :: pid()} |
                        ignore |
                        {error, Reason :: term()}.
start_link(Address, Port, ChannelSup, ChannelOpts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE,
                          {Address, Port, ChannelSup, ChannelOpts}, []).

%% @doc Stops the server.
-spec stop() -> term().
stop() ->
    gen_server:call(?MODULE, stop).

%%------------------------------------------------------------------------------
%% gen_server callbacks
%%------------------------------------------------------------------------------

%% @private Initializes the server.
-spec init({Address :: inet:ip_address(), Port :: inet:port_number(),
            ChannelSup :: pid(), ChannelOpts :: [term()]}) ->
                  {ok, State :: #state{}} |
                  {ok, State :: #state{}, Timeout :: non_neg_integer()} |
                  ignore |
                  {stop, Reason :: term()}.
init({Address, Port, ChannelSup, ChannelOpts}) ->
    {ok, ListenSocket} = gen_tcp:listen(Port, [{active, false}, {ip, Address}]),
    gen_server:cast(self(), accept),
    {ok, #state{listen_socket = ListenSocket,
                ofp_channel_sup = ChannelSup,
                ofp_channel_opts = ChannelOpts}}.

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(accept, #state{listen_socket = ListenSocket,
                           ofp_channel_sup = ChannelSup,
                           ofp_channel_opts = ChannelOpts} = State) ->

    {ok, Socket} = gen_tcp:accept(ListenSocket),
    {ok, Pid} = ofp_channel:open(ChannelSup, controller_id(Socket),
                                 {socket, Socket, tcp}, ChannelOpts),
    gen_tcp:controlling_process(Socket, Pid),
    gen_server:cast(self(), accept),
    {noreply, State};
handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{listen_socket = ListenSocket}) ->
    ok = gen_tcp:close(ListenSocket).

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%------------------------------------------------------------------------------
%% Internal functions
%%------------------------------------------------------------------------------

controller_id(Socket) ->
    {ok, {Address, Port}} = inet:peername(Socket),
    Data = lists:flatten(io_lib:format("~p~p", [Address, Port])),
    "active_controller" ++ re:replace(Data, "({)|(})|(,)", "",
                                      [global, {return, list}]).
