-module(ofp_client_tests).

-include_lib("eunit/include/eunit.hrl").
-include("of_protocol.hrl").
-include("ofp_v4.hrl").

-define(CONTROLLER_LISTEN_ADDRESS, {127, 0, 0, 1}).
-define(DEFAULT_CONTROLLER_ROLE, equal).
-define(DEFAULT_TCP_LISTEN_SOCKET_OPTS, [{ip, ?CONTROLLER_LISTEN_ADDRESS}]).

%% Generators ------------------------------------------------------------------

change_role_generation_id_test_() ->
    {setup,
     fun generation_id_setup/0,
     fun generation_id_teardown/1,
     fun change_roles/1
    }.

version_negotiation_test_() ->
    {setup,
     fun() -> random:seed(erlang:now()) end,
     fun(_) -> ok end,
     {foreach,
      fun version_negotiation_setup/0,
      fun version_negotiation_teardown/1,
      [fun should_send_incompatible_version_error/1,
       fun should_agree_on_1_3_version/1,
       fun should_agree_on_1_3_version__with_bitmap/1]}}.

active_controller_test_() ->
    {foreach,
     fun active_controller_setup/0,
     fun active_controller_teardown/1,
     [fun expect_hello/1,
      fun expect_client_terminate/1]}.

external_role_change_test_() ->
    {foreach,
     fun external_role_change_setup/0,
     fun external_role_change_teardown/1,
     [fun expect_client_change_role_for_1_3_version/1,
      fun expect_client_change_role_for_1_4_version/1,
      fun expect_client_will_send_role_status_to_controller/1]}.

%% Tests ----------------------------------------------------------------------

change_roles(State) ->
    {"Test if the ofp_client responds with the correct generation id "
     "depending on the role request",
     fun() ->
             [begin
                  ok = change_roles(generation_id() - N,
                                    max_generation_id(), N, State)
              end || N <- lists:seq(1, 10)]
     end}.

change_roles(_, _, 0, _) ->
    ok;
change_roles(CurrentGenId, LastGenId, N, State) ->
    Roles = [nochange, equal, master, slave],
    {RoleReply, NewState} =
        ofp_client:change_role(?VERSION, Role = random_list_element(Roles),
                               CurrentGenId, State),
    case Role of
        R when R == nochange orelse R == equal ->
            ?assertEqual(LastGenId,
                         RoleReply#ofp_role_reply.generation_id),
            change_roles(CurrentGenId, LastGenId, N - 1, NewState);
        R when R == master orelse R == slave ->
            ?assertEqual(CurrentGenId,
                         RoleReply#ofp_role_reply.generation_id),
            change_roles(CurrentGenId + 1,
                         RoleReply#ofp_role_reply.generation_id,
                         N - 1,
                         NewState)
    end.

should_send_incompatible_version_error({_, _, ConrollerSocket}) ->
    {"Test if the ofp_client responds with HELLO_FAILED message with "
     "INCOMPATIBLE code if it receives OF message with the version that it "
     "doesn't support",
     fun() ->
             gen_tcp:recv(ConrollerSocket, 0),
             UnsupportedOfVersion = 16#09,
             Message = #ofp_message{version = 4,
                                    xid = get_xid(),
                                    body = #ofp_hello{}},
             {ok, EncodedMessage} = of_protocol:encode(Message),
             gen_tcp:send(ConrollerSocket, change_version_in_of_message(
                                             UnsupportedOfVersion,
                                             EncodedMessage)),
             {ok, EncodedReply} = gen_tcp:recv(ConrollerSocket, 0),
             {ok, Reply, _} = of_protocol:decode(EncodedReply),
             ?assertMatch(#ofp_message{body = #ofp_error_msg{
                                         type = hello_failed,
                                         code = incompatible}}, Reply)
     end}.

should_agree_on_1_3_version({_, _, ConrollerSocket}) ->
    {"Test if the ofp_client agrees on 1.3 OF version after sending hello "
     "message without any hello element; the ofp_client should not send "
     " any error message and keep the connection open",
     fun() ->
             gen_tcp:recv(ConrollerSocket, 0),
             Message = #ofp_message{
               version = 4, xid = get_xid(), body = #ofp_hello{}},
             {ok, EncodedMessage} = of_protocol:encode(Message),
             gen_tcp:send(ConrollerSocket, EncodedMessage),
             ?assertMatch({error, timeout}, gen_tcp:recv(ConrollerSocket, 0, 10))
     end}.

should_agree_on_1_3_version__with_bitmap({_, _, ConrollerSocket}) ->
    {"Test if the ofp_client agrees on 1.3 OF version after sending hello "
     "with bitmap indicating that the controller supports 1.0 and 1.3; "
     "the ofp_client should not send any error message and keep the connection "
     "open",
     fun() ->
             gen_tcp:recv(ConrollerSocket, 0),
             Message = #ofp_message{
               version = 4,
               xid = get_xid(),
               body = #ofp_hello{elements = [{versionbitmap, [1,4]}]}},
             {ok, EncodedMessage} = of_protocol:encode(Message),
             gen_tcp:send(ConrollerSocket, EncodedMessage),
             ?assertMatch({error, timeout}, gen_tcp:recv(ConrollerSocket, 0, 10))
     end}.

expect_hello({Tid, ListenSocket, ControllerSocket}) ->
    {"Test if the ofp_client started with a socket holding an established "
     "connection will send a hello message",
     fun() ->
             {ok, OFPClientSocket} = gen_tcp:accept(ListenSocket),
             {ok, Pid} = ofp_client:start_link(Tid, "ID",
                                                {socket, OFPClientSocket, tcp},
                                                [{versions, [4]}]),
             {ok, BinMsg} = gen_tcp:recv(ControllerSocket, 0),
             {ok, DecodedMsg, _}  = of_protocol:decode(BinMsg),
             ?assertMatch(#ofp_message{body = #ofp_hello{}}, DecodedMsg),
             ofp_client:stop(Pid),
             gen_tcp:close(ControllerSocket)
     end}.

expect_client_terminate({Tid, ListenSocket, ControllerSocket}) ->
    {"Test if the ofp_client started with a socket holding an established "
     "connection will stop when the connection is terminated by the controller",
     fun() ->
             erlang:process_flag(trap_exit, true),
             {ok, OFPClientSocket} = gen_tcp:accept(ListenSocket),
             {ok, Pid} = ofp_client:start_link(Tid, "ID",
                                               {socket, OFPClientSocket, tcp},
                                               [{versions, [4]}]),
             ok = gen_tcp:controlling_process(OFPClientSocket, Pid),
             ok = gen_tcp:close(ControllerSocket),
             ClientTeminatedNormally = receive
                                           {'EXIT', Pid, normal} ->
                                               true
                                       after 3000 ->
                                               false
                                       end,
             ?assert(ClientTeminatedNormally),
             ?assertNot(erlang:is_process_alive(Pid))
     end}.

expect_client_change_role_for_1_3_version({ClientPid, ListenSocket}) ->
    {"Test if ofp_client for 1.3 OF version will change a role for a connection",
     fun() ->
             expect_client_change_role_for_version(ClientPid, ListenSocket, 4)
     end}.

expect_client_change_role_for_1_4_version({ClientPid, ListenSocket}) ->
    {"Test if ofp_client for 1.4 OF version will change a role for a connection",
     fun() ->
             expect_client_change_role_for_version(ClientPid, ListenSocket, 5)
     end}.

expect_client_will_send_role_status_to_controller({ClientPid, ListenSocket}) ->
    {"Test if ofp_client for 1.4 OF version will send a role status message",
     fun() ->
             ControllerSocket  = connect_to_ofp_client_and_request_version(
                                   ListenSocket,5),
             %% Wait a while so that ofp_client can initialize
             timer:sleep(2000),
             assert_ofp_client_agreed_on_version(ClientPid, 5),
             [assert_ofp_client_sent_role_status_when_role_changes(
                ClientPid, ControllerSocket) || _ <- lists:seq(1, 10)],
             gen_tcp:close(ControllerSocket)
     end}.

%% Fixtures -------------------------------------------------------------------

generation_id_setup() ->
    random:seed(erlang:now()),
    mock_ofp_channel(),
    mock_ofp_client_state().

generation_id_teardown(_) ->
    unmock_ofp_channel().

version_negotiation_setup() ->
    ListenSocket = create_tcp_listen_socket(Port = random_port(),
                                            [binary,{active, false}]),
    OFClientPid = start_ofp_clent(Port),
    {ok, ControllerSocket} = gen_tcp:accept(ListenSocket),
    {OFClientPid, ListenSocket, ControllerSocket}.

version_negotiation_teardown({OFClientPid, ListenSocket, ControllerSocket})->
    ofp_client:stop(OFClientPid),
    gen_tcp:close(ControllerSocket),
    gen_tcp:close(ListenSocket).

active_controller_setup() ->
    random:seed(erlang:now()),
    ListenSocket = create_tcp_listen_socket(Port = random_port(), []),
    {ok, ControllerSocket} = gen_tcp:connect(?CONTROLLER_LISTEN_ADDRESS, Port,
                                             [{active, false}, binary]),
    {ets:new(dummy, [public]), ListenSocket, ControllerSocket}.

active_controller_teardown({_Tid, ListenSocket, ControllerSocket}) ->
    ok = gen_tcp:close(ListenSocket),
    ok = gen_tcp:close(ControllerSocket).

external_role_change_setup() ->
    ListenSocket = create_tcp_listen_socket(Port = random_port(),
                                            [binary,{active, false}]),
    OFClientPid = start_ofp_clent(Port),
    {OFClientPid, ListenSocket}.

external_role_change_teardown({OFClientPid, ListenSocket}) ->
    ofp_client:stop(OFClientPid),
    gen_tcp:close(ListenSocket).

%% Helper functions ------------------------------------------------------------

create_tcp_listen_socket(Port, Opts) ->
    {ok, ListenSocket} = gen_tcp:listen(Port,
                                        ?DEFAULT_TCP_LISTEN_SOCKET_OPTS ++ Opts),
    ListenSocket.

start_ofp_clent(Port) ->
    RemotePeer = {remote_peer, ?CONTROLLER_LISTEN_ADDRESS, Port, tcp},
    {ok, OFClientPid} = ofp_client:start_link(ets:new(dummy, [public]),
                                              undefined,
                                              RemotePeer,
                                              [{versions, [3,4,5]}]),
    OFClientPid.

generation_id() ->
    random:uniform(16#FFFFFFFFFFFFFFFF).

max_generation_id() ->
    16#FFFFFFFFFFFFFFFF.

random_list_element(List) ->
    lists:nth(random:uniform(length(List)), List).

mock_ofp_channel() ->
    ok = meck:new(ofp_channel),
    ok = meck:expect(ofp_channel, make_slaves,
                     fun(_, _) ->
                             ok
                     end).

mock_ofp_client_state() ->
    DummyTid = ets:new(dummy, []),
    {ok, State, 0} = ofp_client:init({DummyTid,
                                      resource_id,
                                      {remote_peer, ip, port, proto},
                                      parent,
                                      [],
                                      main,
                                      sup}),
    State.

unmock_ofp_channel() ->
    ok = meck:unload(ofp_channel).

random_port() ->
    random:uniform(49152) + 16383.

get_xid() ->
    random:uniform(1 bsl 32 - 1).

change_version_in_of_message(HexVersion, <<_:8, Rest/binary>>) ->
    <<HexVersion:8, Rest/binary>>.

expect_client_change_role_for_version(ClientPid, ListenSocket, Version) ->
    ControllerSocket  = connect_to_ofp_client_and_request_version(ListenSocket,
                                                                  Version),
    %% Wait a while so that ofp_client can initialize
    timer:sleep(2000),
    assert_ofp_client_agreed_on_version(ClientPid, Version),
    assert_ofp_client_has_role(ClientPid, ?DEFAULT_CONTROLLER_ROLE),
    ok = ofp_client:update_connection_config(ClientPid,
                                             [{role, NewRole = slave}]),
    assert_ofp_client_has_role(ClientPid, NewRole),
    gen_tcp:close(ControllerSocket).

connect_to_ofp_client_and_request_version(ListenSocket, Version) ->
    {ok, ControllerSocket} = gen_tcp:accept(ListenSocket),
    send_hello_with_version(ControllerSocket, Version),
    assert_ofp_client_sent_hello(ControllerSocket),
    ControllerSocket.

send_hello_with_version(ControllerSocket, Version) ->
    Message = #ofp_message{
      version = Version,
      xid = get_xid(),
      body = #ofp_hello{elements = [{versionbitmap, [Version]}]}},
    {ok, EncodedMessage} = of_protocol:encode(Message),
    ok = gen_tcp:send(ControllerSocket, EncodedMessage).

assert_ofp_client_sent_hello(ControllerSocket) ->
    {ok, BinMsg} = gen_tcp:recv(ControllerSocket, 0),
    {ok, DecodedMsg, _}  = of_protocol:decode(BinMsg),
    ?assertMatch(#ofp_message{body = #ofp_hello{}}, DecodedMsg).

assert_ofp_client_agreed_on_version(ClientPid, Version) ->
    ?assertMatch(#controller_status{current_version = Version},
                 gen_server:call(ClientPid, get_controller_state)).

assert_ofp_client_has_role(ClientPid, Role) ->
    ?assertMatch(#controller_status{role = Role},
                 gen_server:call(ClientPid, get_controller_state)).

assert_ofp_client_sent_role_status(ControllerSocket, ExpectedRole) ->
    {ok, BinMsg} = gen_tcp:recv(ControllerSocket, 0),
    {ok, DecodedMsg, RestBinMsg}  = of_protocol:decode(BinMsg),
    assert_message_contains_role_status(DecodedMsg, RestBinMsg, ExpectedRole).

assert_message_contains_role_status(#ofp_message{body = RoleStatus},
                                    _RestBinMsg, ExpectedRole)
  when element(1, RoleStatus) == ofp_role_status->
    ActualRole = element(2, RoleStatus),
    ?assertEqual(ActualRole, ExpectedRole);
assert_message_contains_role_status(_DecodedMsg, <<>>, ExpectedRole) ->
    fail(io_lib:format("The controller didn't send role status with ~p role",
                       [ExpectedRole]));
assert_message_contains_role_status(_DecodedMsg, RestBinMsg, ExpectedRole) ->
    {ok, DecodedMsg2, RestBinMsg2}  = of_protocol:decode(RestBinMsg),
    assert_message_contains_role_status(DecodedMsg2, RestBinMsg2, ExpectedRole).

assert_ofp_client_sent_role_status_when_role_changes(ClientPid,
                                                     ControllerSocket) ->
    NewRole = random_list_element([slave, master, equal]),
    #controller_status{role = CurrentRole} = gen_server:call(
                                               ClientPid, get_controller_state),
    ok = ofp_client:update_connection_config(ClientPid, [{role, NewRole}]),
    case NewRole /= CurrentRole of
        true ->
            assert_ofp_client_sent_role_status(ControllerSocket,
                                               NewRole);
        _ ->
            ok
    end.

fail(Msg) ->
    ?debugMsg(Msg),
    ?assert(false).
