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
%% @doc OpenFlow Protocol library module.
-module(of_protocol).

%% API
-export([encode/1,
         decode/1,
         parse/2]).

-include("of_protocol.hrl").

-export_type([ofp_message/0, ofp_parser/0]).

%%%-----------------------------------------------------------------------------
%%% API functions
%%%-----------------------------------------------------------------------------

%% @doc Encode Erlang representation to binary.
-spec encode(ofp_message()) -> {ok, binary()} | {error, any()}.
encode(#ofp_message{version = Version} = Message) ->
    case ?MOD(Version) of
        undefined ->
            {error, unsupported_version};
        Module ->
            Module:encode(Message)
    end.

%% @doc Decode binary to Erlang representation.
-spec decode(binary()) -> {ok, ofp_message(), binary()} | {error, any()}.
decode(Binary) when byte_size(Binary) >= ?OFP_HEADER_SIZE ->
    <<Version:8, _:8, Length:16, _/bytes>> = Binary,
    case ?MOD(Version) of
        unsupported ->
            {error, unsupported_version};
        Module ->
            case byte_size(Binary) >= Length of
                false ->
                    {error, binary_too_small};
                true ->
                    Module:decode(Binary)
            end
    end;
decode(_Binary) ->
    {error, binary_too_small}.

%% @doc Parse binary to messages in Erlang representation.
-spec parse(ofp_parser(), binary()) -> {ok, ofp_parser(), [ofp_message()]}.
parse(Parser, Binary) ->
    ofp_parser:parse(Parser, Binary).
