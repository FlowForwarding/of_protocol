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
%% @doc OpenFlow Wire Protocol client.
-module(ofp_client).

-behaviour(gen_server).

%% API
-export([start_link/0,
         start_link/1,
         start_link/2,
         start_link/3,
         start_link/4,
         controlling_process/2,
         send/2,
         stop/1]).

%% Internal API
-export([make_slave/1]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-include("of_protocol.hrl").

-define(DEFAULT_HOST, "localhost").
-define(DEFAULT_PORT, 6633).
-define(DEFAULT_VERSION, 4).
-define(DEFAULT_TIMEOUT, timer:seconds(5)).

-record(state, {
          id :: integer(),
          controller :: {string(), integer()},
          aux_connections = [] :: [{tcp, integer()}],
          parent :: pid(),
          version :: integer(),
          versions :: integer(),
          role = equal :: master | equal | slave,
          generation_id :: integer(),
          filter = {{true, true, true}, {true, false, false}},
          socket :: inets:socket(),
          parser :: record(),
          timeout :: integer()
         }).

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

start_link() ->
    start_link(?DEFAULT_HOST).

start_link(Host) ->
    start_link(Host, ?DEFAULT_PORT).

start_link(Host, Port) ->
    start_link(Host, Port, []).

start_link(Host, Port, Opts) ->
    start_link(Host, Port, Opts, main).

%% @doc Start the client.
-spec start_link(string(), integer(), proplists:proplist(),
                 main | {aux, integer(), pid()}) -> {ok, Pid :: pid()} |
                                                    ignore |
                                                    {error, Error :: term()}.
start_link(Host, Port, Opts, Type) ->
    Parent = get_opt(controlling_process, Opts, self()),
    gen_server:start_link(?MODULE, {{Host, Port}, Parent, Opts, Type}, []).

%% @doc Change the controlling process.
-spec controlling_process(pid(), pid()) -> ok.
controlling_process(Pid, ControllingPid) ->
    gen_server:call(Pid, {controlling_process, ControllingPid}).

%% @doc Send a message.
%% Valid messages include all the reply and async messages from all version of
%% the OpenFlow Protocol specification. Attempt so send any other message will
%% result in {error, {bad_message, Message :: ofp_message()}}.
-spec send(pid(), ofp_message()) -> ok | {error, Reason :: term()}.
send(Pid, Message) ->
    gen_server:call(Pid, {send, Message}).

%% @doc Stop the client.
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:call(Pid, stop).

%%------------------------------------------------------------------------------
%% Internal API functions
%%------------------------------------------------------------------------------

make_slave(Pid) ->
    gen_server:call(Pid, make_slave).

%%------------------------------------------------------------------------------
%% gen_server callbacks
%%------------------------------------------------------------------------------

init({Controller, Parent, Opts, Type}) ->
    Version = get_opt(version, Opts, ?DEFAULT_VERSION),
    Versions = lists:umerge(get_opt(versions, Opts, []), [Version]),
    Timeout = get_opt(timeout, Opts, ?DEFAULT_TIMEOUT),
    State = #state{controller = Controller,
                   parent = Parent,
                   versions = Versions,
                   timeout = Timeout},
    case Type of
        main ->
            ets:insert(ofp_channel, {main, self()}),
            AuxConnections = get_opt(auxiliary_connections, Opts, []),
            {ok, State#state{id = 0,
                             aux_connections = AuxConnections}, 0};
        {aux, Id, Pid} ->
            ets:insert(ofp_channel, {Pid, self()}),
            {ok, State#state{id = Id}, 0}
    end.

handle_call({send, _Message}, _From, #state{socket = undefined} = State) ->
    {reply, {error, not_connected}, State};
handle_call({send, _Message}, _From, #state{parser = undefined} = State) ->
    {reply, {error, parser_not_ready}, State};
handle_call({send, Message}, _From, #state{version = Version} = State) ->
    Message2 = add_type(Message#ofp_message{version = Version}),
    case Message2#ofp_message.type of
        Type when Type == error;
                  Type == echo_reply;
                  Type == features_reply;
                  Type == get_config_reply;
                  Type == packet_in;
                  Type == flow_removed;
                  Type == port_status;
                  Type == stats_reply;
                  Type == multipart_reply;
                  Type == barrier_reply;
                  Type == queue_get_config_reply;
                  Type == role_reply;
                  Type == get_async_reply ->
            {reply, handle_send(Message2, State), State};
        _Else ->
            {reply, {error, {bad_message, Message2}}, State}
    end;
handle_call({controlling_process, Pid}, _From, State) ->
    {reply, ok, State#state{parent = Pid}};
handle_call(make_slave, _From, #state{role = master} = State) ->
    %% Make auxiliary connections slave as well
    [make_slave(Pid) || {_, Pid} <- ets:lookup(ofp_channel, self())],
    {reply, ok, State#state{role = slave}};
handle_call(stop, _From, State) ->
    {stop, normal, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(timeout, #state{id = Id,
                            controller = {Host, Port},
                            parent = ControllingProcess,
                            aux_connections = AuxConnections,
                            versions = Versions,
                            timeout = Timeout} = State) ->
    %% Try to connect to the controller
    TCPOpts = [binary, {active, once}],
    case gen_tcp:connect(Host, Port, TCPOpts) of
        {ok, Socket} ->
            case Id of
                0 ->
                    %% Open auxiliary connections
                    Opts = [{controlling_process, ControllingProcess},
                            {versions, Versions},
                            {timeout, Timeout}],
                    TCPAux = get_opt(tcp, AuxConnections, 0),
                    [begin
                         Args = [Host, Port, Opts, {aux, AuxId, self()}],
                         {ok, Pid} = supervisor:start_child(ofp_channel_sup,
                                                            Args),
                         ets:insert(ofp_channel, {self(), Pid})
                     end || AuxId <- lists:seq(1, TCPAux)];
                _ ->
                    ok
            end,

            {ok, HelloBin} = of_protocol:encode(create_hello(Versions)),
            ok = gen_tcp:send(Socket, HelloBin),
            {noreply, State#state{socket = Socket}};
        {error, _Reason} ->
            {noreply, State, Timeout}
    end;
handle_info({tcp, Socket, Data}, #state{id = Id,
                                        controller = {Host, Port},
                                        socket = Socket,
                                        parent = Parent,
                                        parser = undefined,
                                        version = undefined,
                                        versions = Versions} = State) ->
    inet:setopts(Socket, [{active, once}]),
    %% Wait for hello
    case of_protocol:decode(Data) of
        {ok, #ofp_message{version = CtrlVersion,
                          xid = Xid,
                          body = #ofp_hello{}} = Hello, Leftovers} ->
            case decide_on_version(Versions, Hello) of
                {unsupported_version, _} ->
                    Error = create_error(CtrlVersion,
                                         hello_failed, incompatible),
                    ErrorMsg = #ofp_message{version = CtrlVersion,
                                            xid = Xid,
                                            body = Error},
                    {ok, ErrorBin} = of_protocol:encode(ErrorMsg),
                    ok = gen_tcp:send(Socket, ErrorBin),
                    self() ! {tcp, Socket, Leftovers},
                    {noreply, State#state{version = lists:max(Versions)}};
                {no_common_version, _, _} = Reason ->
                    reset_connection(State, Reason);
                Version ->
                    Parent ! {ofp_connected, self(),
                              {Host, Port, Id, Version}},
                    {ok, Parser} = ofp_parser:new(Version),
                    self() ! {tcp, Socket, Leftovers},
                    {noreply, State#state{parser = Parser,
                                          version = Version}}
            end;
        _Else ->
            reset_connection(State, bad_initial_message)
    end;
handle_info({tcp, Socket, Data}, #state{id = Id,
                                        controller = {Host, Port},
                                        socket = Socket,
                                        parent = Parent,
                                        parser = undefined,
                                        version = Version} = State) ->
    inet:setopts(Socket, [{active, once}]),
    %% Wait for hello_failed error message
    case of_protocol:decode(Data) of
        {ok, #ofp_message{version = Version,
                          xid = 0} = Message, Leftovers} ->
            Message2 = add_type(Message),
            case Message2#ofp_message.type of
                error_msg ->
                    reset_connection(State, {failed_negotation, Version});
                _Else ->
                    Parent ! {ofp_connected, self(),
                              {Host, Port, Id, Version}},
                    self() ! {tcp, Socket, Data},
                    {ok, Parser} = ofp_parser:new(Version),
                    {noreply, State#state{parser = Parser}}
            end;
        _Else ->
            reset_connection(State, bad_message)
    end;
handle_info({tcp, Socket, Data}, #state{socket = Socket,
                                        parser = Parser} = State) ->
    inet:setopts(Socket, [{active, once}]),

    case ofp_parser:parse(Parser, Data) of
        {ok, NewParser, Messages} ->
            Handle = fun(Message, Acc) ->
                             handle_message(Message, Acc)
                     end,
            NewState = lists:foldl(Handle, State, Messages),
            {noreply, NewState#state{parser = NewParser}};
        _Else ->
            reset_connection(State, {bad_data, Data})
    end;
handle_info({tcp_closed, Socket}, #state{socket = Socket} = State) ->
    reset_connection(State, tcp_closed);
handle_info({tcp_error, Socket, Reason}, #state{socket = Socket} = State) ->
    reset_connection(State, {tcp_error, Reason});
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{id = Id}) ->
    case Id of
        0 ->
            ets:delete_object(ofp_channel, {main, self()}),
            ets:delete(ofp_channel, self());
        _ ->
            ok
    end,

    io:format("Terminating ~p ~p~n", [Id, self()]).

code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

%%------------------------------------------------------------------------------
%% Internal functions
%%------------------------------------------------------------------------------

handle_send(#ofp_message{type = features_reply} = Message,
            #state{id = Id} = State) ->
    do_send(add_aux_id(Message, Id), State);
handle_send(#ofp_message{type = packet_in} = Message,
            #state{id = Id} = State) ->
    case Id of
        0 ->
            case ets:lookup(ofp_channel, self()) of
                [] ->
                    do_filter_send(Message, State);
                List ->
                    RandomIndex = random:uniform(length(List)),
                    {_, AuxPid} = lists:nth(RandomIndex, List),
                    send(AuxPid, Message)
            end;
        _Else ->
            do_filter_send(Message, State)
    end;
handle_send(Message, State) ->
    do_filter_send(Message, State).

do_send(Message, #state{socket = Socket,
                        parser = Parser,
                        version = Version}) ->
    case ofp_parser:encode(Parser, Message#ofp_message{version = Version}) of
        {ok, Binary} ->
            Size = byte_size(Binary),
            case Size < (1 bsl 16) of
                true ->
                    gen_tcp:send(Socket, Binary);
                false ->
                    {error, message_too_big}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

do_filter_send(Message, #state{role = Role, filter = Filter} = State) ->
    case filter_message(Message, Role, Filter) of
        true ->
            do_send(Message, State);
        false ->
            {error, filtered}
    end.

handle_message(#ofp_message{type = role_request, version = Version,
                            body = RoleRequest} = Message, State) ->
    {Role, GenId} = extract_role(Version, RoleRequest),
    {Reply, NewState} = change_role(Version, Role, GenId, State),
    do_send(Message#ofp_message{body = Reply}, State),
    NewState;
handle_message(#ofp_message{type = get_async_request,
                            version = Version} = Message,
               #state{filter = Filter} = State) ->
    AsyncReply = create_async(Version, Filter),
    do_send(Message#ofp_message{body = AsyncReply}, State),
    State;
handle_message(#ofp_message{type = set_async, version = Version,
                            body = SetAsync},
               #state{filter = _Filter} = State) ->
    Filter = extract_async(Version, SetAsync),
    State#state{filter = Filter};
handle_message(#ofp_message{version = Version, type = Type} = Message,
               #state{role = slave} = State)
  when Type == flow_mod;
       Type == group_mod;
       Type == port_mod;
       Type == table_mod;
       Type == meter_mod ->
    %% Don't allow slave controllers to modify things.
    Error = create_error(Version, bad_request, is_slave),
    IsSlaveError = Message#ofp_message{body = Error},
    do_send(IsSlaveError, State);
handle_message(#ofp_message{type = Type} = Message,
               #state{parent = Parent} = State)
  when Type == echo_request;
       Type == features_request;
       Type == get_config_request;
       Type == set_config;
       Type == packet_out;
       Type == flow_mod;
       Type == group_mod;
       Type == port_mod;
       Type == table_mod;
       Type == stats_request;
       Type == multipart_request;
       Type == barrier_request;
       Type == queue_get_config_request;
       Type == meter_mod ->
    Parent ! {ofp_message, self(), Message},
    State;
handle_message(_OtherMessage, State) ->
    State.

create_hello(Versions) ->
    Version = lists:max(Versions),
    Body = if
               Version >= 4 ->
                   #ofp_hello{elements = [{versionbitmap, Versions}]};
               true ->
                   #ofp_hello{}
           end,
    #ofp_message{version = Version, xid = 0, body = Body}.

decide_on_version(CVersions, #ofp_message{version = SVersion, body = Body}) ->
    CVersion = lists:max(CVersions),
    if
        CVersion >= 4 ->
            case CVersion == SVersion of
                true ->
                    CVersion;
                false ->
                    if
                        SVersion >= 4 ->
                            Elements = Body#ofp_hello.elements,
                            SVersions = get_opt(versionbitmap, Elements, []),
                            SVersions2 = lists:umerge([SVersion], SVersions),
                            case gcv(CVersions, SVersions2) of
                                no_common_version ->
                                    {no_common_version, CVersions, SVersions};
                                Version ->
                                    Version
                            end;
                        true ->
                            case lists:member(SVersion, CVersions) of
                                true ->
                                    SVersion;
                                false ->
                                    {unsupported_version, SVersion}
                            end
                    end
            end;
        true ->
            case lists:member(SVersion, CVersions) of
                true ->
                    SVersion;
                false ->
                    {unsupported_version, SVersion}
            end
    end.

filter_message(#ofp_message{type = Type}, Role, {MasterEqual, Slave}) ->
    {PacketIn, PortStatus, FlowRemoved} =
        case Role of
            slave ->
                Slave;
            _Else ->
                MasterEqual
        end,
    case Type of
        packet_in ->
            PacketIn;
        port_status ->
            PortStatus;
        flow_removed ->
            FlowRemoved;
        _Other ->
            true
    end.

change_role(Version, nochange, GenId, #state{role = Role} = State) ->
    RoleReply = create_role(Version, Role, GenId),
    {RoleReply, State};
change_role(Version, equal, GenId, State) ->
    RoleReply = create_role(Version, equal, GenId),
    {RoleReply, State#state{role = equal}};
change_role(Version, Role, GenId,
            #state{generation_id = CurrentGenId} = State) ->
    if
        (CurrentGenId /= undefined)
        andalso (GenId - CurrentGenId < 0) ->
            ErrorReply = create_error(Version, role_request_failed, stale),
            {ErrorReply, State};
        true ->
            case Role of
                master ->
                    ofp_channel:make_slaves(self());
                slave ->
                    ok
            end,
            RoleReply = create_role(Version, Role, GenId),
            {RoleReply, State#state{role = Role,
                                    generation_id = GenId}}
    end.

%%------------------------------------------------------------------------------
%% Helper functions
%%------------------------------------------------------------------------------

get_opt(Opt, Opts, Default) ->
    case lists:keyfind(Opt, 1, Opts) of
        false ->
            Default;
        {Opt, Value} ->
            Value
    end.

%% @doc Greatest common version.
gcv([], _) ->
    no_common_version;
gcv(_, []) ->
    no_common_version;
gcv([CV | _], [SV | _]) when CV == SV ->
    CV;
gcv([CV | CVs], [SV | _] = SVs) when CV > SV ->
    gcv(CVs, SVs);
gcv([CV | _] = CVs, [SV | SVs]) when CV < SV ->
    gcv(CVs, SVs).

reset_connection(#state{id = Id,
                        controller = {Host, Port},
                        socket = Socket,
                        parent = Parent,
                        timeout = Timeout} = State, Reason) ->
    %% Close the socket
    case Socket of
        undefined ->
            ok;
        Socket ->
            gen_tcp:close(Socket)
    end,

    case Id of
        0 ->
            %% Terminate auxiliary connections
            [supervisor:terminate_child(ofp_channel_sup, Pid)
             || {_, Pid} <- ets:lookup(ofp_channel, self())],
            ets:delete(ofp_channel, self());
        _ ->
            ok
    end,

    %% Notify the parent
    Parent ! {ofp_closed, self(), {Host, Port, Id, Reason}},

    %% Reset
    {noreply, State#state{socket = undefined,
                          parser = undefined}, Timeout}.

create_error(3, Type, Code) ->
    ofp_client_v3:create_error(Type, Code);
create_error(4, Type, Code) ->
    ofp_client_v4:create_error(Type, Code).

create_role(3, Role, GenId) ->
    ofp_client_v3:create_role(Role, GenId);
create_role(4, Role, GenId) ->
    ofp_client_v4:create_role(Role, GenId).

extract_role(3, RoleRequest) ->
    ofp_client_v3:extract_role(RoleRequest);
extract_role(4, RoleRequest) ->
    ofp_client_v4:extract_role(RoleRequest).

create_async(4, Masks) ->
    ofp_client_v4:create_async(Masks).

extract_async(4, Async) ->
    ofp_client_v4:extract_async(Async).

add_type(#ofp_message{version = Version, body = Body} = Message) ->
    case Version of
        3 ->
            Message#ofp_message{type = ofp_client_v3:type_atom(Body)};
        4 ->
            Message#ofp_message{type = ofp_client_v4:type_atom(Body)}
    end.

add_aux_id(#ofp_message{version = Version, body = Body} = Message, Id) ->
    case Version of
        3 ->
            Message;
        4 ->
            Message#ofp_message{body = ofp_client_v4:add_aux_id(Body, Id)}
    end.
