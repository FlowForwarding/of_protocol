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
%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org
%% @doc OpenFlow Protocol parser.
-module(ofp_parser).

%% API
-export([new/0, parse/2]).

-include("of_protocol.hrl").

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

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
