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
-export([new/1,
         parse/2,
         encode/2]).

-include("of_protocol.hrl").

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

-spec new(integer()) -> {ok, ofp_parser()}.
new(Version) ->
    case ?MOD(Version) of
        unsupported ->
            {error, unsupported_version};
        Module ->
            {ok, #ofp_parser{version = Version,
                             module = Module}}
    end.

%% @doc Parse binary to OpenFlow Protocol messages.
-spec parse(ofp_parser(), binary()) -> {ok, ofp_parser(), [ofp_message()]}.
parse(Parser, Binary) ->
    {ok, NewParser, Messages} = parse(Binary, Parser, []),
    {ok, NewParser, lists:reverse(Messages)}.

%% @doc Encode a message using a parser.
-spec encode(ofp_parser(), ofp_message()) -> {ok, Binary :: binary()} |
                                             {error, Reason :: term()}.
encode(#ofp_parser{module = Module}, Message) ->
    Module:encode(Message).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-spec parse(binary(), ofp_parser(), [ofp_message()]) ->
                   {ok, binary(), [ofp_message()]}.
parse(Binary, #ofp_parser{module = Module, stack = Stack} = Parser, Messages) ->
    NewBinary = <<Stack/binary, Binary/binary>>,
    case Module:decode(NewBinary) of
        {error, binary_too_small} ->
            {ok, Parser#ofp_parser{stack = NewBinary}, Messages};
        {error, _} ->
            {ok, Parser#ofp_parser{stack = <<>>}, Messages};
        {ok, Message, Leftovers} ->
            parse(Leftovers, Parser#ofp_parser{stack = <<>>},
                  [Message | Messages])
    end.
