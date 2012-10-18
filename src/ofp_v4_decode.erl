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
decode_body(error, Binary) ->
    <<TypeInt:16, More/bytes>> = Binary,
    Type = ofp_v4_enum:to_atom(error_type, TypeInt),
    case Type of
        experimenter ->
            DataLength = size(Binary) - ?ERROR_EXPERIMENTER_SIZE + ?OFP_HEADER_SIZE,
            <<ExpTypeInt:16, Experimenter:32, Data:DataLength/bytes>> = More,
            #ofp_error_msg_experimenter{exp_type = ExpTypeInt,
                                        experimenter = Experimenter,
                                        data = Data};
        _ ->
            DataLength = size(Binary) - ?ERROR_SIZE + ?OFP_HEADER_SIZE,
            <<CodeInt:16, Data:DataLength/bytes>> = More,
            Code = ofp_v4_enum:to_atom(Type, CodeInt),
            #ofp_error_msg{type = Type,
                           code = Code, data = Data}
    end;
decode_body(echo_request, Binary) ->
    DataLength = size(Binary) - ?ECHO_REQUEST_SIZE + ?OFP_HEADER_SIZE,
    <<Data:DataLength/bytes>> = Binary,
    #ofp_echo_request{data = Data};
decode_body(echo_reply, Binary) ->
    DataLength = size(Binary) - ?ECHO_REPLY_SIZE + ?OFP_HEADER_SIZE,
    <<Data:DataLength/bytes>> = Binary,
    #ofp_echo_reply{data = Data};
decode_body(experimenter, Binary) ->
    DataLength = size(Binary) - ?EXPERIMENTER_SIZE + ?OFP_HEADER_SIZE,
    <<Experimenter:32, Type:32, Data:DataLength/bytes>> = Binary,
    #ofp_experimenter{experimenter = Experimenter,
                      exp_type = Type, data = Data};
decode_body(features_request, _) ->
    #ofp_features_request{};
decode_body(features_reply, Binary) ->
    <<DataPathMac:48/bits, DataPathID:16, NBuffers:32,
      NTables:8, AuxId:8, 0:16, CapaBin:32/bits, 0:32>> = Binary,
    Capabilities = binary_to_flags(capabilities, CapaBin),
    #ofp_features_reply{datapath_mac = DataPathMac,
                        datapath_id = DataPathID, n_buffers = NBuffers,
                        n_tables = NTables, auxiliary_id = AuxId,
                        capabilities = Capabilities};
decode_body(get_config_request, _) ->
    #ofp_get_config_request{};
decode_body(get_config_reply, Binary) ->
    <<FlagsBin:16/bits, Miss:16>> = Binary,
    Flags = binary_to_flags(config_flags, FlagsBin),
    #ofp_get_config_reply{flags = Flags,
                          miss_send_len = Miss};
decode_body(set_config, Binary) ->
    <<FlagsBin:16/bits, Miss:16>> = Binary,
    Flags = binary_to_flags(config_flags, FlagsBin),
    #ofp_set_config{flags = Flags, miss_send_len = Miss};
decode_body(barrier_request, _) ->
    #ofp_barrier_request{};
decode_body(barrier_reply, _) ->
    #ofp_barrier_reply{}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

binary_to_flags(Type, Binary) ->
    ofp_utils:binary_to_flags(ofp_v4_enum, Type, Binary).
