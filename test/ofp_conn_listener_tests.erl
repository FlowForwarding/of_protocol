-module(ofp_conn_listener_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LISTEN_ADDRESS, {127,0,0,1}).
-define(CHANNEL_SUP, list_to_pid("<0.0.15>")).
-define(CHANNEL_OPTS, []).
-define(TEST_DATA, "TEST").


basic_operation_test_() ->
    {setup,
     fun() -> ok = meck:new(ofp_channel) end,
     fun(_) -> ok = meck:unload(ofp_channel) end,
     {"Test basic operation of ofp_conn_listener: start/connect/stop",
      fun() ->
              ok = meck:expect(ofp_channel, open, 4,
                               {ok, list_to_pid("<0.0.4>")}),
              Port = random_port(),
              ?assertMatch(
                 {ok, Pid} when is_pid(Pid), ofp_conn_listener:start_link(
                                               ?LISTEN_ADDRESS, Port,
                                               list_to_pid("<0.0.5>"), [])),
              {ok, Socket} = gen_tcp:connect(?LISTEN_ADDRESS, Port,
                                             [{active, false}]),
              ?assert(ok =:= ofp_conn_listener:stop()),
              ?assertEqual(undefined, whereis(ofp_conn_listener)),
              gen_tcp:close(Socket)
      end}}.

new_connections_test_() ->
    {foreach,
     fun setup/0,
     fun teardown/1,
     [fun accept_incoming_connection/1,
      fun open_ofp_channel/1,
      fun handle_multiple_connections/1]}.

accept_incoming_connection({State, ListenPort}) ->
    {"Test if the ofp_conn_listener will accept an incoming tcp connection",
     fun() ->
             meck:expect(ofp_channel, open,
                         fun(_, _, {socket, AcceptedSocket, tcp}, _) ->
                                 gen_tcp:send(AcceptedSocket, ?TEST_DATA),
                                 {ok, list_to_pid("<0.0.1>")}
                         end),
             {ok, Socket} = gen_tcp:connect(?LISTEN_ADDRESS, ListenPort,
                                            [{active, false}]),
             ofp_conn_listener:handle_cast(accept, State),
             {ok, {Address, Port}} = inet:peername(Socket),
             ?assertEqual(?LISTEN_ADDRESS, Address),
             ?assertEqual(ListenPort, Port),
             ?assertEqual({ok, ?TEST_DATA}, gen_tcp:recv(Socket, 0)),
             gen_tcp:close(Socket)
     end}.

open_ofp_channel({State, ListenPort}) ->
    {"Test if the ofp_conn_listener will open an ofp_channel after accepting "
     "a connection a give it an ownership to the opened socket",
     fun() ->
             ChannelName = dummy_chanel,
             AckSockName = accepted_socket,

             meck:expect(M = ofp_channel, F = open,
                         fun(_, _, {socket, AcceptedSocket, tcp}, _) ->
                                 true = register(AckSockName, AcceptedSocket),
                                 true = register(ChannelName,
                                                 Pid = dummy_channel()),
                                 {ok, Pid}
                         end),

             {ok, Socket} = gen_tcp:connect(?LISTEN_ADDRESS, ListenPort,
                                            [{active, false}]),
             ofp_conn_listener:handle_cast(accept, State),

             ChannelPid = whereis(ChannelName),
             {connected, AckSockOwner} = erlang:port_info(whereis(AckSockName),
                                                          connected),

             ?assert(meck:called(M, F,
                                 [?CHANNEL_SUP, '_', '_', ?CHANNEL_OPTS])),
             ?assertEqual(ChannelPid, AckSockOwner),

             exit(ChannelPid, kill),
             gen_tcp:close(Socket)
     end}.

handle_multiple_connections({State, ListenPort}) ->
    {"Test if the ofp_conn_listener will be able to handle multiple connections",
     [fun() ->
              ChannelName = dummy_channel,
              meck:expect(ofp_channel, open,
                          fun(_, _, _, _) ->
                                  true = register(ChannelName,
                                                  Pid = dummy_channel()),
                                  {ok, Pid}
                          end),
              {ok, Socket} = gen_tcp:connect(?LISTEN_ADDRESS, ListenPort,
                                             [{active, false}]),
              ofp_conn_listener:handle_cast(accept, State),
              exit(whereis(ChannelName), kill),
              gen_tcp:close(Socket)
      end || _ <- lists:seq(1, 10)]}.

%% Fixtures -------------------------------------------------------------------

setup() ->
    {ok, State} = ofp_conn_listener:init({?LISTEN_ADDRESS, ListenPort = random_port(),
                                          ?CHANNEL_SUP, ?CHANNEL_OPTS}),
    ok = meck:new(ofp_channel),
    {State, ListenPort}.

teardown({State, _Port}) ->
    ok = meck:unload(ofp_channel),
    ok = ofp_conn_listener:terminate(shutdown, State).

%%------------------------------------------------------------------------------
%% Internal functions
%%------------------------------------------------------------------------------

random_port() ->
    random:seed(erlang:now()),
    random:uniform(49152) + 16383.

dummy_channel() ->
    spawn(fun() ->
                  timer:sleep(infinity)
          end).
