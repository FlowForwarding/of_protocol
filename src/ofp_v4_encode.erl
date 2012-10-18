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
%% @doc OpenFlow Protocol 1.3 (4) encoding implementation.
%% @private
-module(ofp_v4_encode).

-export([do/1]).

-include("of_protocol.hrl").
-include("ofp_v4.hrl").

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

%% @doc Actual encoding of the message.
-spec do(Message :: ofp_message()) -> binary().
do(#ofp_message{version = Version, xid = Xid, body = Body}) ->
    BodyBin = encode_body(Body),
    TypeInt = type_int(Body),
    Length = ?OFP_HEADER_SIZE + size(BodyBin),
    <<Version:8, TypeInt:8, Length:16, Xid:32, BodyBin/bytes>>.

%%------------------------------------------------------------------------------
%% Encode functions
%%------------------------------------------------------------------------------

%% Structures ------------------------------------------------------------------

%% %%% Messages -------------------------------------------------------------------

encode_body(#ofp_hello{}) ->
    <<>>;
encode_body(#ofp_error_msg{type = Type, code = Code, data = Data}) ->
    TypeInt = ofp_v4_enum:to_int(error_type, Type),
    CodeInt = ofp_v4_enum:to_int(Type, Code),
    <<TypeInt:16, CodeInt:16, Data/bytes>>;
encode_body(#ofp_error_msg_experimenter{exp_type = ExpTypeInt,
                                        experimenter = Experimenter,
                                        data = Data}) ->
    TypeInt = ofp_v4_enum:to_int(error_type, experimenter),
    <<TypeInt:16, ExpTypeInt:16, Experimenter:32, Data/bytes>>;
encode_body(#ofp_echo_request{data = Data}) ->
    Data;
encode_body(#ofp_echo_reply{data = Data}) ->
    Data;
encode_body(#ofp_experimenter{experimenter = Experimenter,
                              exp_type = Type, data = Data}) ->
    <<Experimenter:32, Type:32, Data/bytes>>;
encode_body(#ofp_barrier_request{}) ->
    <<>>;
encode_body(#ofp_barrier_reply{}) ->
    <<>>.

%% %%------------------------------------------------------------------------------
%% %% Helper functions
%% %%------------------------------------------------------------------------------

-spec type_int(ofp_message_body()) -> integer().
type_int(#ofp_hello{}) ->
    ofp_v4_enum:to_int(type, hello);
type_int(#ofp_error_msg{}) ->
    ofp_v4_enum:to_int(type, error);
type_int(#ofp_error_msg_experimenter{}) ->
    ofp_v4_enum:to_int(type, error);
type_int(#ofp_echo_request{}) ->
    ofp_v4_enum:to_int(type, echo_request);
type_int(#ofp_echo_reply{}) ->
    ofp_v4_enum:to_int(type, echo_reply);
type_int(#ofp_experimenter{}) ->
    ofp_v3_enum:to_int(type, experimenter);
type_int(#ofp_barrier_request{}) ->
    ofp_v4_enum:to_int(type, barrier_request);
type_int(#ofp_barrier_reply{}) ->
    ofp_v4_enum:to_int(type, barrier_reply).
