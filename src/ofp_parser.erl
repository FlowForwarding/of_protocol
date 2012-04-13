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

%% @doc Create new parser.
-spec new() -> {ok, ofp_parser()}.
new() ->
    {ok, #ofp_parser{}}.

%% @doc Parse binary to OpenFlow Protocol messages.
-spec parse(Parser :: ofp_parser(), Binary :: binary()) ->
                   {ok, ofp_parser(), [ofp_message()]}.
parse(Parser = #ofp_parser{stack = Stack}, Binary) ->
    {ok, NewStack, Messages} = parse(Binary, Stack, []),
    {ok, Parser#ofp_parser{stack = NewStack}, lists:reverse(Messages)}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-spec parse(Binary :: binary(), Stack :: binary(),
            Messages :: [ofp_message()]) -> {ok, binary(), [ofp_message()]}.
parse(Binary, Stack, Messages) ->
    NewBinary = << Stack/binary, Binary/binary >>,
    case of_protocol:decode(NewBinary) of
        {error, binary_too_small} ->
            {ok, NewBinary, Messages};
        {error, _} ->
            {ok, <<>>, Messages};
        {ok, Message, Leftovers} ->
            parse(Leftovers, <<>>, [Message | Messages])
    end.
