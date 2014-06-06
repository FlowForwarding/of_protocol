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

-ifdef(TEST).
-compile([export_all]).
-endif.

%% API
-export([start_link/4,
         start_link/5,
         controlling_process/2,
         send/2,
         stop/1,
         update_connection_config/2,
         get_controllers_state/1,
         get_resource_ids/1]).

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
-include_lib("kernel/include/inet.hrl").

-define(DEFAULT_HOST, "localhost").
-define(DEFAULT_PORT, 6633).
-define(DEFAULT_VERSION, 4).
-define(DEFAULT_TIMEOUT, timer:seconds(3)).

-record(state, {
          id :: integer(),
          resource_id :: string(),
          controller :: {string(), integer(), atom()},
          aux_connections = [] :: [{tcp, integer()}],
          parent :: pid(),
          version :: integer(),
          versions :: [integer()],
          role = equal :: controller_role(),
          generation_id :: integer(),
          filter = #async_config{},
          socket :: inet:socket(),
          parser :: ofp_parser(),
          timeout :: integer(),
          supervisor :: pid(),
          ets :: ets:tid(),
          hello_buffer = <<>> :: binary(),
          reconnect :: true | false
         }).

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

start_link(Tid, ResourceId, ControllerHandle, Opts) ->
    start_link(Tid, ResourceId, ControllerHandle, Opts, main).

%% @doc Starts the client.
%%
%% For more information on `ControllerHandle' see {@link ofp_channel:open/4}.
-spec start_link(Tid :: ets:tid(), ResourceId :: string(),
                 ControllerHandle ::
                   {remote_peer, inet:ip_address(), inet:port_number(), Proto} |
                   {socket, inet:socket(), Proto},
                 Opts :: proplists:proplist(),
                 Type :: main | {aux, integer(), pid()}) ->
                        {ok, Pid :: pid()} | ignore |
                        {error, Error :: term()} when
      Proto :: tcp | tls.
start_link(Tid, ResourceId, ControllerHandle, Opts, Type) ->
    Parent = get_opt(controlling_process, Opts, self()),
    gen_server:start_link(?MODULE, {Tid, ResourceId, ControllerHandle, Parent,
                                    Opts, Type, self()}, []).

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

%% @doc Update the connection to the controller.
%%
%% If the list of configuration tuples doesn't contain some value, the value will
%% be taken from the current configuration. For example, to change only the port
%% of a controller the client is expected to connect to (without changing the IP
%% address etc.), one needs to create the following configuration:
%% [{port, 6634}].
-spec update_connection_config(pid(), list(ConfigTuple)) -> ok when
      ConfigTuple :: {ip, inet:ip_address()} |
                     {protocol, tcp | tls} |
                     {prort, inet:port_number()} |
                     {role, controller_role()}.
update_connection_config(Pid, Config) ->
    gen_server:cast(Pid, {update_connection_config, Config}).

%% @doc Stop the client.
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:call(Pid, stop).

-spec get_controllers_state(integer()) -> [#controller_status{}].
get_controllers_state(SwitchId) ->
    Tid = ofp_channel:get_ets(SwitchId),
    lists:map(fun({main, Pid}) ->
                      gen_server:call(Pid, get_controller_state)
              end, ets:lookup(Tid, main)).

get_resource_ids(SwitchId) ->
    Tid = ofp_channel:get_ets(SwitchId),
    lists:map(fun({main, Pid}) ->
                      {Pid, gen_server:call(Pid, get_resource_id)}
              end, ets:lookup(Tid, main)).

%%------------------------------------------------------------------------------
%% Internal API functions
%%------------------------------------------------------------------------------

make_slave(Pid) ->
    gen_server:call(Pid, make_slave).

%%------------------------------------------------------------------------------
%% gen_server callbacks
%%------------------------------------------------------------------------------

%% @doc Initializes the ofp_client.
%%
%% The ofp_client can start in two different ways depending on the
%% `ControllerHandle'. If this variable is a tuple tagged with remote_peer
%% the client will attempt to connect to the controller. On the other hand,
%% if the variable is a tuple tagged with socket the client will assume that
%% the connection has already been established and move on to sending hello
%% message. For more information on `ControllerHandle' see
%% {@link ofp_channel:open/4}.
init({Tid, ResourceId, ControllerHandle, Parent, Opts, Type, Sup}) ->
    %% The current implementation of TCP sockets in LING throws exceptions on
    %% errors that occur outside the context of a gen_tcp call. We have to
    %% catch these exceptions not to confuse the supervisor.
    process_flag(trap_exit, true),
    Version = get_opt(version, Opts, ?DEFAULT_VERSION),
    Versions = lists:umerge(get_opt(versions, Opts, []), [Version]),
    Timeout = get_opt(timeout, Opts, ?DEFAULT_TIMEOUT),
    State1 = #state{resource_id = ResourceId,
                   parent = Parent,
                   versions = Versions,
                   timeout = Timeout,
                   supervisor = Sup,
                   ets = Tid},
    State2 = init_controller_handle(ControllerHandle, State1),
    State3 = init_aux_connections(Tid, Opts, Type, State2),
    {ok, State3, 0}.

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
                  Type == get_async_reply;
                  Type == bundle_ctrl_msg ->
            {reply, handle_send(Message2, State), State};
        _Else ->
            {reply, {error, {bad_message, Message2}}, State}
    end;
handle_call({controlling_process, Pid}, _From, State) ->
    {reply, ok, State#state{parent = Pid}};
handle_call(make_slave, _From, #state{role = master,
                                      ets = Tid,
                                      version = Version,
                                      generation_id = CurrentGenId} = State) ->
    if Version >= 5 ->
            RoleStatus =
                case CurrentGenId of
                    undefined ->
                        role_status(Version, slave, master_request, max_generation_id());
                    _ ->
                        role_status(Version, slave, master_request, CurrentGenId)
                end,
            do_send(#ofp_message{body = RoleStatus}, State);
       true ->
            do_nothing
    end,
    %% Make auxiliary connections slave as well
    [make_slave(Pid) || {_, Pid} <- ets:lookup(Tid, self())],
    {reply, ok, State#state{role = slave}};
handle_call(get_resource_id, _From, #state{resource_id = ResourceId} = State) ->
    {reply, ResourceId, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(get_controller_state, _From, #state{controller = {ControllerIP,
                                                              ControllerPort,
                                                              Protocol},
                                                resource_id = ResourceId,
                                                role = Role,
                                                socket = Socket,
                                                version = CurrentVersion,
                                                versions = SupportedVersions
                                               } = State) ->
    Controller = controller_state(ControllerIP, ControllerPort,
                                  ResourceId, Role, Socket, Protocol,
                                  CurrentVersion, SupportedVersions),
    {reply, Controller, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({update_connection_config, Config},
            #state{controller = {IP, Port, Protocol}} = State) ->
    NewController = {proplists:get_value(ip, Config, IP),
                     proplists:get_value(port, Config, Port),
                     proplists:get_value(protocol, Config, Protocol)},
    NewRole = proplists:get_value(role, Config),
    NewState1 = reestablish_connection_if_required(NewController, State),
    NewState2 = change_role_if_required(NewRole, NewState1),
    {noreply, NewState2};
handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(timeout, #state{resource_id = ResourceId,
                            id = Id,
                            controller = {Host, Port, Proto},
                            parent = ControllingProcess,
                            aux_connections = AuxConnections,
                            versions = Versions,
                            socket = undefined,
                            timeout = Timeout,
                            supervisor = Sup,
                            ets = Tid} = State) ->
    %% Try to connect to the controller
    case connect(Proto, Host, Port) of
        {ok, Socket} ->
            case Id of
                0 ->
                    %% Open auxiliary connections
                    Opts = [{controlling_process, ControllingProcess},
                            {versions, Versions},
                            {timeout, Timeout}],
                    TCPAux = get_opt(tcp, AuxConnections, 0),
                    [begin
                         Args = [generate_aux_resource_id(ResourceId, AuxId),
                                 {remote_peer, Host, Port, tcp},
                                 Opts, {aux, AuxId, self()}],
                         {ok, Pid} = supervisor:start_child(Sup, Args),
                         ets:insert(Tid, {self(), Pid})
                     end || AuxId <- lists:seq(1, TCPAux)],
                    TLSAux = get_opt(tls, AuxConnections, 0),
                    [begin
                         Args = [generate_aux_resource_id(ResourceId, AuxId),
                                 {remote_peer, Host, Port, tls},
                                 Opts, {aux, AuxId, self()}],
                         {ok, Pid} = supervisor:start_child(Sup, Args),
                         ets:insert(Tid, {self(), Pid})
                     end || AuxId <- lists:seq(1, TLSAux)];
                _ ->
                    ok
            end,

            {ok, HelloBin} = of_protocol:encode(create_hello(Versions)),
            ok = send(Proto, Socket, HelloBin),
            {noreply, State#state{socket = Socket}};
        {error, _Reason} ->
            erlang:send_after(Timeout, self(), timeout),
            {noreply, State}
    end;
handle_info(timeout, #state{controller = {_Host, _Port, Proto},
                            versions = Versions,
                            socket = Socket}  = State) ->
    {ok, HelloBin} = of_protocol:encode(create_hello(Versions)),
    send(Proto, Socket, HelloBin),
    setopts(Proto, Socket, opts(tcp)),
    {noreply, State};
handle_info({Type, Socket, Data}, #state{id = Id,
                                         controller = {Host, Port, Proto},
                                         socket = Socket,
                                         parent = Parent,
                                         parser = undefined,
                                         version = undefined,
                                         versions = Versions,
                                         hello_buffer = Buffer} = State)
  when Type == tcp orelse Type == ssl ->
    setopts(Proto, Socket, [{active, once}]),
    %% Wait for hello
    case of_protocol:decode(<<Buffer/binary, Data/binary>>) of
        {ok, #ofp_message{xid = Xid, body = #ofp_hello{}} = Hello, Leftovers} ->
            case decide_on_version(Versions, Hello) of
                {failed, Reason} ->
                    handle_failed_negotiation(Xid, Reason, State);
                Version ->
                    Parent ! {ofp_connected, self(),
                              {Host, Port, Id, Version}},
                    {ok, Parser} = ofp_parser:new(Version),
                    self() ! {tcp, Socket, Leftovers},
                    {noreply, State#state{parser = Parser,
                                          version = Version}}
            end;
        {error, binary_too_small} ->
            {noreply, State#state{hello_buffer = <<Buffer/binary,
                                                   Data/binary>>}};
        {error, unsupported_version, Xid} ->
            handle_failed_negotiation(Xid, unsupported_version_or_bad_message,
                                      State)
    end;
handle_info({Type, Socket, Data}, #state{controller = {_, _, Proto},
                                         socket = Socket,
                                         parser = Parser} = State)
  when Type == tcp orelse Type == ssl ->
    setopts(Proto, Socket, [{active, once}]),

    case ofp_parser:parse(Parser, Data) of
        {ok, NewParser, Messages} ->
            Handle = fun(Message, Acc) ->
                             handle_message(Message, Acc)
                     end,
            NewState = lists:foldl(Handle, State, Messages),
            {noreply, NewState#state{parser = NewParser}};
        _Else ->
            terminate_connection_then_reconnect_or_stop(State, {bad_data, Data})
    end;
handle_info({Type, Socket}, #state{socket = Socket} = State)
  when Type == tcp_closed orelse Type == ssl_closed ->
    terminate_connection_then_reconnect_or_stop(State, Type);
handle_info({Type, Socket, Reason}, #state{socket = Socket} = State)
  when Type == tcp_error orelse Type == ssl_error ->
    terminate_connection_then_reconnect_or_stop(State, {Type, Reason});
handle_info({'EXIT', Socket, Reason}, #state{socket = Socket} = State) ->
    %% LING-specific. We have caught an asynchronous error from the socket.
    %% It is time to terminate gracefully.
    terminate_connection_then_reconnect_or_stop(State, Reason);
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{id = Id,
                          ets = Tid}) ->
    case Id of
        0 ->
            ets:delete_object(Tid, {main, self()}),
            ets:delete(Tid, self());
        _ ->
            ok
    end.

code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

%%------------------------------------------------------------------------------
%% Internal functions
%%------------------------------------------------------------------------------

handle_send(#ofp_message{type = features_reply} = Message,
            #state{id = Id} = State) ->
    do_send(add_aux_id(Message, Id), State);
handle_send(#ofp_message{type = packet_in} = Message,
            #state{id = Id,
                   ets = Tid} = State) ->
    case Id of
        0 ->
            case ets:lookup(Tid, self()) of
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
handle_send(#ofp_message{type = Type} = Message, 
            #state{version = Version} = State) when Type =:= multipart_reply ->
    Module = client_module(Version),
    Replies = Module:split_multipart(Message),
    Result = [do_send(Reply, State) || Reply <- Replies],
    case lists:all(fun(X) -> X == ok end,lists:flatten(Result)) of
        true ->
            ok;
        false ->
            {error, bad_multipart_split}
    end;
handle_send(Message, State) ->
    do_filter_send(Message, State).

do_send(#ofp_message{ type = Type } = Message, #state{controller = {_, _, Proto},
                      socket = Socket,
                      parser = Parser,
                      version = Version} = State) when Type =:= multipart_reply ->
    case ofp_parser:encode(Parser, Message#ofp_message{version = Version}) of
        {ok, Binary} ->
            case byte_size(Binary) < (1 bsl 16) of
                true ->
                    send(Proto, Socket, Binary);
                false ->
                    Module = client_module(Version),
                    case Module:split_big_multipart(Message) of
                        false ->
                            {error, message_too_big};
                        SplitList ->
                            lists:map(fun(Msg) -> do_send(Msg,State) end, SplitList)
                    end
            end;
        {error, Reason} ->
            {error, Reason}
    end;
do_send(Message, #state{controller = {_, _, Proto},
                        socket = Socket,
                        parser = Parser,
                        version = Version}) ->
    case ofp_parser:encode(Parser, Message#ofp_message{version = Version}) of
        {ok, Binary} ->
            Size = byte_size(Binary),
            case Size < (1 bsl 16) of
                true ->
                    send(Proto, Socket, Binary);
                false ->
                    {error, message_too_big}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

do_filter_send(#ofp_message{version = Version} = Message,
               #state{role = Role, filter = Filter} = State)
  when Version >= 4 ->
    Module = client_module(Version),
    case Module:filter_out_message(Message, Role, Filter) of
        false ->
            do_send(Message, State);
        true ->
            {ok, filtered}
    end;
do_filter_send(Message, State) ->
    do_send(Message, State).

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
       Type == meter_mod;
       Type == bundle_control;
       Type == bundle_add_message ->
    %% Don't allow slave controllers to modify things.
    Error = create_error(Version, bad_request, is_slave),
    IsSlaveError = Message#ofp_message{body = Error},
    do_send(IsSlaveError, State),
    State;
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
       Type == meter_mod;
       Type == bundle_control;
       Type == bundle_add_message ->
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

decide_on_version(SupportedVersions, #ofp_message{version = CtrlHighestVersion,
                                                  body = HelloBody}) ->
    SupportedHighestVersion = lists:max(SupportedVersions),
    if
        SupportedHighestVersion == CtrlHighestVersion ->
            SupportedHighestVersion;
        SupportedHighestVersion >= 4 andalso CtrlHighestVersion >= 4 ->
            decide_on_version_with_bitmap(SupportedVersions, CtrlHighestVersion,
                                          HelloBody);
        true ->
            decide_on_version_without_bitmap(SupportedVersions,
                                             CtrlHighestVersion)
    end.

decide_on_version_with_bitmap(SupportedVersions, CtrlHighestVersion,
                              HelloBody) ->
    Elements = HelloBody#ofp_hello.elements,
    SwitchVersions = get_opt(versionbitmap, Elements, []),
    SwitchVersions2 = lists:umerge([CtrlHighestVersion], SwitchVersions),
    case greatest_common_version(SupportedVersions, SwitchVersions2) of
        no_common_version ->
            {failed, {no_common_version, SupportedVersions, SwitchVersions2}};
        Version ->
            Version
    end.

decide_on_version_without_bitmap(SupportedVersions, CtrlHighestVersion) ->
    case lists:member(CtrlHighestVersion, SupportedVersions) of
        true ->
            CtrlHighestVersion;
        false ->
            {failed, {unsupported_version, CtrlHighestVersion}}
    end.

change_role(Version, nochange, _GenId,
            #state{role = Role,
                   generation_id = CurrentGenId} = State) ->
    RoleReply = case CurrentGenId of
                    undefined ->
                        create_role(Version, Role, max_generation_id());
                    _ ->
                        create_role(Version, Role, CurrentGenId)
                end,
    {RoleReply, State};
change_role(Version, equal, _GenId,
            #state{generation_id = CurrentGenId} = State) ->
    RoleReply = case CurrentGenId of
                    undefined ->
                        create_role(Version, equal, max_generation_id());
                    _ ->
                        create_role(Version, equal, CurrentGenId)
                end,
    {RoleReply, State#state{role = equal}};
change_role(Version, Role, GenId,
            #state{generation_id = CurrentGenId,
                   ets = Tid} = State) ->
    if
        (CurrentGenId /= undefined)
        andalso (GenId - CurrentGenId < 0) ->
            ErrorReply = create_error(Version, role_request_failed, stale),
            {ErrorReply, State};
        true ->
            case Role of
                master ->
                    ofp_channel:make_slaves(Tid, self());
                slave ->
                    ok
            end,
            RoleReply = create_role(Version, Role, GenId),
            {RoleReply, State#state{role = Role,
                                    generation_id = GenId}}
    end.

controller_state(ConfigControllerIP, ConfigControllerPort, ResourceId, Role,
                 Socket, Protocol, CurrentVersion, SupportedVersions) ->
    {ControllerIP, ControllerPort, LocalIP, LocalPort} =
        case Socket of
            undefined ->
                {ConfigControllerIP, ConfigControllerPort,
                 undefined, undefined};
            _ ->
                {ok, {CIP, CPort}} = inet:peername(Socket),
                {ok, {LIP, LPort}} = inet:sockname(Socket),
                {CIP, CPort, LIP, LPort}
        end,
    ConnectionState = case {Socket, CurrentVersion} of
                          %% Socket to controller not yet opened
                          {undefined, _} ->
                              down;
                          %% Socket to controller opened,
                          %% but hello message with version not received yet
                          {_, undefined} ->
                              down;
                          {_, _} ->
                              up
                      end,
    #controller_status{
       resource_id = ResourceId,
       role = Role,
       controller_ip = ControllerIP,
       controller_port = ControllerPort,
       local_ip = LocalIP,
       local_port = LocalPort,
       protocol = Protocol,
       connection_state = ConnectionState,
       current_version = CurrentVersion,
       supported_versions = SupportedVersions}.

%%------------------------------------------------------------------------------
%% Helper functions
%%------------------------------------------------------------------------------

send_incompatible_version_error(Xid, Socket, Proto, OFVersion) ->
    ErrorMessageBody = create_error(OFVersion, hello_failed, incompatible),
    ErrorMessage = #ofp_message{version = OFVersion,
                                xid = Xid,
                                body = ErrorMessageBody},
    {ok, EncodedErrorMessage} = of_protocol:encode(ErrorMessage),
    ok = send(Proto, Socket, EncodedErrorMessage).

handle_failed_negotiation(Xid, Reason, #state{socket = Socket,
                                              controller = {_, _, Proto},
                                              versions = Versions} = State) ->
    send_incompatible_version_error(Xid, Socket, Proto,
                                    lists:max(Versions)),
    terminate_connection_then_reconnect_or_stop(State, Reason).

init_controller_handle({remote_peer, Host, Port, Proto}, #state{} = State) ->
    State#state{
      controller = {Host, Port, Proto}, socket = undefined, reconnect = true};
init_controller_handle({socket, Socket, Proto}, #state{} = State) ->
    {ok, {Address, Port}} = inet:peername(Socket),
    Host = retrieve_hostname_from_address(Address),
    State#state{
      controller = {Host, Port, Proto}, socket = Socket, reconnect = false}.

init_aux_connections(Tid, Opts, main, #state{} = State) ->
    ets:insert(Tid, {main, self()}),
    AuxConnections = get_opt(auxiliary_connections, Opts, []),
    State#state{id = 0, aux_connections = AuxConnections};
init_aux_connections(Tid, _Opts, {aux, AuxId, Pid}, #state{} = State) ->
    ets:insert(Tid, {Pid, self()}),
    State#state{id = AuxId}.

retrieve_hostname_from_address(Address) ->
    case inet:gethostbyaddr(Address) of
        {ok, Hostent} when Hostent#hostent.h_name =/= undefined ->
            Hostent#hostent.h_name;
        _ ->
            inet_parse:ntoa(Address)
    end.


get_opt(Opt, Opts, Default) ->
    case lists:keyfind(Opt, 1, Opts) of
        false ->
            Default;
        {Opt, Value} ->
            Value
    end.

%% @doc Greatest common version.
greatest_common_version([], _) ->
    no_common_version;
greatest_common_version(_, []) ->
    no_common_version;
greatest_common_version(ControllerVersions, SwitchVersions) ->
    case [CtrlVersion || CtrlVersion <- ControllerVersions,
                         lists:member(CtrlVersion, SwitchVersions)] of
        [] ->
            no_common_version;
        [_|_] = CommonVersions ->
            lists:max(CommonVersions)
    end.

terminate_connection_then_reconnect_or_stop(State, Reason) ->
    NewState = terminate_connection(State, Reason),
    case State#state.reconnect of
        true ->
            reconnect(State#state.timeout),
            {noreply, NewState};
        false ->
            {stop, normal, NewState}
    end.

terminate_connection(#state{id = Id,
                            controller = {Host, Port, Proto},
                            socket = Socket,
                            parent = Parent,
                            supervisor = Sup,
                            ets = Tid} = State, Reason) ->
    close(Proto, Socket),
    terminate_auxiliary_connections(Id, Sup, Tid),
    ets:delete(Tid, self()),
    Parent ! {ofp_closed, self(), {Host, Port, Id, Reason}},
    State#state{socket = undefined, parser = undefined, version = undefined,
                hello_buffer = <<>>}.

reconnect(Timeout) ->
    erlang:send_after(Timeout, self(), timeout).

terminate_auxiliary_connections(0, _, _) ->
    ok;
terminate_auxiliary_connections(_Id, Sup, Tid) ->
    [supervisor:terminate_child(Sup, Pid)
     || {_, Pid} <- ets:lookup(Tid, self())].

client_module(3) -> ofp_client_v3;
client_module(4) -> ofp_client_v4;
client_module(5) -> ofp_client_v5.

create_error(Version, Type, Code) ->
    (client_module(Version)):create_error(Type, Code).

create_role(Version, Role, GenId) ->
    (client_module(Version)):create_role(Role, GenId).

extract_role(Version, RoleRequest) ->
    (client_module(Version)):extract_role(RoleRequest).

role_status(Version, Role, Reason, GenId) when Version >= 5 ->
    (client_module(Version)):role_status(Role, Reason, GenId).

create_async(Version, Masks) when Version >= 4 ->
    (client_module(Version)):create_async(Masks).

extract_async(Version, Async) when Version >= 4 ->
    (client_module(Version)):extract_async(Async).

add_type(#ofp_message{version = Version, body = Body} = Message) ->
    Module = client_module(Version),
    Message#ofp_message{type = Module:type_atom(Body)}.

add_aux_id(#ofp_message{version = Version, body = Body} = Message, Id) ->
    case Version of
        3 ->
            Message;
        _ ->
            Module = client_module(Version),
            Message#ofp_message{body = Module:add_aux_id(Body, Id)}
    end.

%% TLS

connect(tcp, Host, Port) ->
    gen_tcp:connect(Host, Port, opts(tcp), 5000);
connect(tls, Host, Port) ->
    case linc_ofconfig:get_certificates() of
        [] ->
            {error, no_certificates};
        Cs ->
            Certs = [base64:decode(C) || {_, C} <- Cs],
            ssl:connect(Host, Port, [{cacerts, Certs} | opts(tls)], 5000)
    end.

opts(tcp) ->
    [binary, {reuseaddr, true}, {active, once}];
opts(tls) ->
    opts(tcp) ++ [{verify, verify_peer},
                  {fail_if_no_peer_cert, true}]
        ++ [{cert, base64:decode(Cert)}
            || {ok, Cert} <- [application:get_env(linc, certificate)]]
        ++ [{key, {'RSAPrivateKey', base64:decode(Key)}}
            || {ok, Key} <- [application:get_env(linc, rsa_private_key)]].

setopts(tcp, Socket, Opts) ->
    inet:setopts(Socket, Opts);
setopts(tls, Socket, Opts) ->
    ssl:setopts(Socket, Opts).

send(tcp, Socket, Data) ->
    gen_tcp:send(Socket, Data);
send(tls, Socket, Data) ->
    ssl:send(Socket, Data).

close(_, undefined) ->
    ok;
close(tcp, Socket) ->
    gen_tcp:close(Socket);
close(tls, Socket) ->
    ssl:close(Socket).

-spec generate_aux_resource_id(string(), integer()) -> string().
generate_aux_resource_id(MainResourceId, AuxId) ->
    MainResourceId ++ "_aux" ++ AuxId.

max_generation_id() ->
    16#FFFFFFFFFFFFFFFF.

send_role_status(NewRole, Reason, #state{version = Version,
                                         generation_id = CurrentGenId} = State)
  when is_integer(Version) andalso Version >= 5 ->
    RoleStatus =
        role_status(Version, NewRole, Reason, case CurrentGenId of
                                                  undefined ->
                                                      max_generation_id();
                                                  _ ->
                                                      CurrentGenId
                                              end),
    do_send(#ofp_message{body = RoleStatus}, State);
send_role_status(_NewRole, _Reason, #state{version = _LowerThan5}) ->
    ok.

reestablish_connection_if_required(NewController, State) ->
    case NewController /= State#state.controller of
        true when is_port(State#state.socket) ->
            %% The client is connected to the controller
            NewState = terminate_connection(State,
                                            external_connection_config_update),
            reconnect(NewState#state.timeout),
            NewState#state{controller = NewController};
        true ->
            State#state{controller = NewController};
        false ->
            State
    end.

%% @doc This function changes the controller's role as a result of internal
%% configuration change.
%%
%% NOTE: This is different from changing role through OpenFlow Protocol. It is
%% implemented in change_role/4. The function below should be invoked when
%% the role is changed through OF-Config.
change_role_if_required(NewRole, #state{role = OldRole} = State)
  when NewRole == OldRole ->
    State;
change_role_if_required(NewRole, #state{id = Id, ets = Tid} = State) ->
    case NewRole of
        master ->
            ofp_channel:make_slaves(Tid, self());
        _ ->
            ok
    end,
    case Id of
        0 ->
            [update_connection_config(AuxPid, [{role, NewRole}])
             ||  {_, AuxPid} <- ets:lookup(Tid, self())];
        _ ->
            ok
    end,
    send_role_status(NewRole, config, State),
    State#state{role = NewRole}.
