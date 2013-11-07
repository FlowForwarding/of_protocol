-module(ofp_parser_tests).

-include_lib("eunit/include/eunit.hrl").
-include("of_protocol.hrl").
-include("ofp_v4.hrl").

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

hello() ->
    <<16#04, 16#00, 16#00, 16#10, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#01, 16#00, 16#08, 16#00, 16#00, 16#00, 16#10>>.

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
