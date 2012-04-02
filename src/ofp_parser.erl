%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%%% @doc OpenFlow Protocol parser.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_parser).

%% API
-export([new/0, parse/2]).

-include("of_protocol.hrl").

%%%-----------------------------------------------------------------------------
%%% API functions
%%%-----------------------------------------------------------------------------

-spec new() -> {ok, #parser{}}.
new() ->
    {ok, #parser{}}.

-spec parse(#parser{}, binary()) -> {ok, #parser{}, [ofp_message()]}.
parse(Parser = #parser{stack = Stack}, Binary) ->
    {ok, NewStack, Structs} = parse(Binary, Stack, []),
    {ok, Parser#parser{stack = NewStack}, lists:reverse(Structs)}.

-spec parse(binary(), binary(), [ofp_message()]) -> {ok, binary(), [ofp_message()]}.
parse(Binary, Stack, Structs) ->
    NewBinary = << Stack/binary, Binary/binary >>,
    case of_protocol:decode(NewBinary) of
        {error, _} ->
            {ok, NewBinary, Structs};
        {ok, Struct, Leftovers} ->
            parse(Leftovers, <<>>, [Struct | Structs])
    end.
