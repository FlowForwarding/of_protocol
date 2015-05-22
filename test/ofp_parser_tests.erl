-module(ofp_parser_tests).

-include_lib("eunit/include/eunit.hrl").
-include("of_protocol.hrl").
-include("ofp_v4.hrl").

%% Tests

parse_test_() ->
    {ok, Parser} = ofp_parser:new(4),
    ?_assertMatch(
       {ok, _, [#ofp_message{body = #ofp_hello{}}]},
       ofp_parser:parse(Parser, hello())).

fragmented_parse_test_() ->
    {ok, Parser} = ofp_parser:new(4),
    [{"parse 8 bytes at a time",
      ?_assertMatch(
         {_, [#ofp_message{body = #ofp_hello{}}]},
         parse_all_fragments(Parser, hello_fragments(8)))},
     {"parse 7 bytes at a time",
      ?_assertMatch(
         {_, [#ofp_message{body = #ofp_hello{}}]},
         parse_all_fragments(Parser, hello_fragments(7)))}].

%% @doc Test that packet-in message for a buffered packet is parsed correctly.
%%
%% This test is to confirm that the 'total_len' field of the packet-in
%% message is not interpreted as the length of the packet portion enclosed
%% in the packet-in message data field.
packet_in_test_() ->
    %% TODO: Refactor
    {ok, Parser} = ofp_parser:new(4),
    ?_assertMatch({ok, _, [#ofp_message{body = #ofp_packet_in{}}]},
                  ofp_parser:parse(Parser, packet_in())).

%% Internal functions

hello() ->
    <<16#04, 16#00, 16#00, 16#10, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#01, 16#00, 16#08, 16#00, 16#00, 16#00, 16#10>>.

%% @doc Creates packet-in message for buffered packet.
%%
%% The message is for a packet that is buffered on the switch that
%% sends only first 30 bytes of the packet in the packet-in message.
%%
%% Packet-in explanation:
%% version: 4
%% type: OFPT_PACKET_IN (10)
%% length: 72
%% xid: 0
%% buffer_id: 4294967295
%% total_len: 42
%% reason: OFPR_ACTION(1)
%% table_id: 0
%% cookie: 0
%% ofp_match
%%    type: OFPMT_OXM (1)
%%    length: 12
%%    of_oxm list
%%       of_oxm_in_port
%%          type_len: 2147483652
%%          value: 1
%% Ethernet packet - 30 bytes
packet_in() ->
    <<16#04, 16#0a, 16#00, 16#48, 16#00, 16#00, 16#00, 16#00, % ofp_header
      16#ff, 16#ff, 16#ff, 16#ff,  % packet-in: bueffer_id
      16#00, 16#2a,  % packet-in: total-len
      16#01, 16#00,  % packet-in: reason and table_id
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,  % packet-in: cookie
      16#00, 16#01,  % packet-in: ofp_match.type
      16#00, 16#0c,  % packet-in: ofp_match.length
      16#80, 16#00, 16#00, 16#04, 16#00, 16#00, 16#00, 16#01, % packet-in: ofp_match.oxm_fields
      16#00, 16#00, 16#00, 16#00, % packet0in: ofp_match.pad
      16#00, 16#00, % packet-in: 2 byte of all-zero pading
      %% packet-in: data (30-bytes Ethernet Packet)
      16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#82, 16#17, 16#60,
      16#f9, 16#43, 16#43, 16#08, 16#06, 16#00, 16#01, 16#08, 16#00,
      16#06, 16#04, 16#00, 16#01, 16#82, 16#17, 16#60, 16#f9, 16#43,
      16#43, 16#0a, 16#00>>.

hello_fragments(Size) ->
    fragments(Size, hello()).

fragments(Size, Binary) ->
    case Binary of
        <<Fragment:Size/binary, Rest/binary>> ->
            [Fragment | fragments(Size, Rest)];
        <<Rest/binary>> ->
            [Rest]
    end.

parse_all_fragments(Parser, Fragments) ->
    lists:foldl(
      fun(Fragment, {Parser1, Messages}) ->
              {ok, Parser2, NewMessages} = ofp_parser:parse(Parser1, Fragment),
              {Parser2, Messages ++ NewMessages}
      end, {Parser, []}, Fragments).
