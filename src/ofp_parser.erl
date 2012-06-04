%%%-----------------------------------------------------------------------------
%%% Use is subject to License terms.
%%% @copyright (C) 2012 FlowForwarding.org
%%% @doc OpenFlow Protocol parser.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_parser).
-author("Erlang Solutions Ltd. <openflow@erlang-solutions.com>").

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
-spec parse(ofp_parser(), binary()) -> {ok, ofp_parser(), [ofp_message()]}.
parse(#ofp_parser{stack = Stack} = Parser, Binary) ->
    {ok, NewStack, Messages} = parse(Binary, Stack, []),
    {ok, Parser#ofp_parser{stack = NewStack}, lists:reverse(Messages)}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-spec parse(binary(), binary(), [ofp_message()]) ->
                   {ok, binary(), [ofp_message()]}.
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
