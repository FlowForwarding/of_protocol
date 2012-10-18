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
%% @author Konrad Kaplita <konrad.kaplita@erlang-solutions.com>
%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org
%% @doc OpenFlow Protocol 1.3 (4) decoding implementation.
%% @private
-module(ofp_v4_decode).

-export([do/1]).

-include("of_protocol.hrl").
-include("ofp_v4.hrl").

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

%% @doc Actual decoding of the message.
-spec do(Binary :: binary()) -> ofp_message().
do(Binary) ->
    <<Version:8, TypeInt:8, _:16, XID:32, BodyBin/bytes >> = Binary,
    Type = ofp_v4_enum:to_atom(type, TypeInt),
    Body = decode_body(Type, BodyBin),
    #ofp_message{version = Version, xid = XID, body = Body}.

%%------------------------------------------------------------------------------
%% Decode functions
%%------------------------------------------------------------------------------

%% Structures ------------------------------------------------------------------

%% @doc Actual decoding of the messages
-spec decode_body(atom(), binary()) -> ofp_message().
decode_body(hello, _) ->
    #ofp_hello{};
decode_body(echo_request, Binary) ->
    DataLength = size(Binary) - ?ECHO_REQUEST_SIZE + ?OFP_HEADER_SIZE,
    <<Data:DataLength/bytes>> = Binary,
    #ofp_echo_request{data = Data};
decode_body(echo_reply, Binary) ->
    DataLength = size(Binary) - ?ECHO_REPLY_SIZE + ?OFP_HEADER_SIZE,
    <<Data:DataLength/bytes>> = Binary,
    #ofp_echo_reply{data = Data};
decode_body(barrier_request, _) ->
    #ofp_barrier_request{};
decode_body(barrier_reply, _) ->
    #ofp_barrier_reply{}.

%% %%%-----------------------------------------------------------------------------
%% %%% Internal functions
%% %%%-----------------------------------------------------------------------------
