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

%% @doc Decode match structure
decode_match(Binary) ->
    PadFieldsLength = size(Binary) - ?MATCH_SIZE + 4,
    <<1:16, NoPadLength:16, PadFieldsBin:PadFieldsLength/bytes>> = Binary,
    FieldsBinLength = (NoPadLength - 4),
    Padding = (PadFieldsLength - FieldsBinLength) * 8,
    <<FieldsBin:FieldsBinLength/bytes, 0:Padding>> = PadFieldsBin,
    Fields = decode_match_fields(FieldsBin),
    #ofp_match{fields = Fields}.

%% @doc Decode match fields
decode_match_fields(Binary) ->
    decode_match_fields(Binary, []).

%% @doc Decode match fields
decode_match_fields(<<>>, Fields) ->
    lists:reverse(Fields);
decode_match_fields(Binary, Fields) ->
    {Field, Rest} = decode_match_field(Binary),
    decode_match_fields(Rest, [Field | Fields]).

%% @doc Decode single match field
decode_match_field(<<Header:4/bytes, Binary/bytes>>) ->
    <<ClassInt:16, FieldInt:7, HasMaskInt:1,
      Length:8>> = Header,
    Class = ofp_v4_enum:to_atom(oxm_class, ClassInt),
    Field = ofp_v4_enum:to_atom(oxm_ofb_match_fields, FieldInt),
    HasMask = (HasMaskInt =:= 1),
    case Class of
        openflow_basic ->
            BitLength = ofp_v4_map:tlv_length(Field);
        _ ->
            BitLength = Length * 4
    end,
    case HasMask of
        false ->
            <<Value:Length/bytes, Rest/bytes>> = Binary,
            TLV = #ofp_field{value = ofp_utils:cut_bits(Value, BitLength)};
        true ->
            Length2 = (Length div 2),
            <<Value:Length2/bytes, Mask:Length2/bytes,
              Rest/bytes>> = Binary,
            TLV = #ofp_field{value = ofp_utils:cut_bits(Value, BitLength),
                             mask = ofp_utils:cut_bits(Mask, BitLength)}
    end,
    {TLV#ofp_field{class = Class,
                   name = Field,
                   has_mask = HasMask}, Rest}.

%% @doc Decode port structure.
decode_port(Binary) ->
    <<PortNoInt:32, 0:32, HWAddr:6/bytes, 0:16, NameBin:16/bytes,
      ConfigBin:4/bytes, StateBin:4/bytes, CurrBin:4/bytes,
      AdvertisedBin:4/bytes, SupportedBin:4/bytes, PeerBin:4/bytes,
      CurrSpeed:32, MaxSpeed:32>> = Binary,
    PortNo = get_id(port_no, PortNoInt),
    Name = ofp_utils:strip_string(NameBin),
    Config = binary_to_flags(port_config, ConfigBin),
    State = binary_to_flags(port_state, StateBin),
    Curr = binary_to_flags(port_features, CurrBin),
    Advertised = binary_to_flags(port_features, AdvertisedBin),
    Supported = binary_to_flags(port_features, SupportedBin),
    Peer = binary_to_flags(port_features, PeerBin),
    #ofp_port{port_no = PortNo, hw_addr = HWAddr, name = Name,
              config = Config, state = State, curr = Curr,
              advertised = Advertised, supported = Supported,
              peer = Peer, curr_speed = CurrSpeed, max_speed = MaxSpeed}.

%% @doc Decode queues
decode_queues(Binary) ->
    decode_queues(Binary, []).

decode_queues(<<>>, Queues) ->
    lists:reverse(Queues);
decode_queues(Binary, Queues) ->
    <<QueueId:32, Port:32, Length:16, 0:48, Data/bytes>> = Binary,
    PropsLength = Length - ?PACKET_QUEUE_SIZE,
    <<PropsBin:PropsLength/bytes, Rest/bytes>> = Data,
    Props = decode_properties(PropsBin),
    Queue = #ofp_packet_queue{queue_id = QueueId, port_no = Port,
                              properties = Props},
    decode_queues(Rest, [Queue | Queues]).

%% @doc Decode queue properties
decode_properties(Binary) ->
    decode_properties(Binary, []).

decode_properties(<<>>, Properties) ->
    lists:reverse(Properties);
decode_properties(Binary, Properties) ->
    <<TypeInt:16, Length:16, 0:32,
      Data/bytes>> = Binary,
    Type = ofp_v3_enum:to_atom(queue_properties, TypeInt),
    case Type of
        min_rate ->
            <<Rate:16, 0:48, Rest/bytes>> = Data,
            Property = #ofp_queue_prop_min_rate{rate = Rate};
        max_rate ->
            <<Rate:16, 0:48, Rest/bytes>> = Data,
            Property = #ofp_queue_prop_max_rate{rate = Rate};
        experimenter ->
            DataLength = Length - ?QUEUE_PROP_EXPERIMENTER_SIZE,
            <<Experimenter:32, 0:32, ExpData:DataLength/bytes,
              Rest/bytes>> = Data,
            Property = #ofp_queue_prop_experimenter{experimenter = Experimenter,
                                                    data = ExpData}
    end,
    decode_properties(Rest, [Property | Properties]).

%% @doc Decode bitmasks in async messages.
decode_async_masks(<<PacketInMaskBin1:32/bits, PacketInMaskBin2:32/bits,
                     PortReasonMaskBin1:32/bits, PortReasonMaskBin2:32/bits,
                     FlowRemovedMaskBin1:32/bits, FlowRemovedMaskBin2:32/bits>>) ->
    PacketInMask1 = binary_to_flags(packet_in_reason, PacketInMaskBin1),
    PacketInMask2 = binary_to_flags(packet_in_reason, PacketInMaskBin2),
    PortStatusMask1 = binary_to_flags(port_reason, PortReasonMaskBin1),
    PortStatusMask2 = binary_to_flags(port_reason, PortReasonMaskBin2),
    FlowRemovedMask1 = binary_to_flags(flow_removed_reason,
                                       FlowRemovedMaskBin1),
    FlowRemovedMask2 = binary_to_flags(flow_removed_reason,
                                       FlowRemovedMaskBin2),
    {{PacketInMask1, PacketInMask2},
     {PortStatusMask1, PortStatusMask2},
     {FlowRemovedMask1, FlowRemovedMask2}}.

%% @doc Decode meter mod bands
decode_bands(Binary) ->
    decode_bands(Binary, []).

decode_bands(<<>>, Bands) ->
    lists:reverse(Bands);
decode_bands(Binary, Bands) ->
    <<TypeInt:16, _Length:16, Rate:32, BurstSize:32, Data/bytes>> = Binary,
    Type = ofp_v4_enum:to_atom(meter_band_type, TypeInt),
    case Type of
        drop ->
            Rest = Data,
            Band = #ofp_meter_band_drop{type = drop, rate = Rate,
                                        burst_size = BurstSize};
        dscp_remark ->
            <<PrecLevel:8, Rest/bytes>> = Data,
            Band = #ofp_meter_band_dscp_remark{type = dscp_remark, rate = Rate,
                                               burst_size = BurstSize,
                                               prec_level = PrecLevel};
        experimenter ->
            <<Experimenter:32, Rest/bytes>> = Data,
            Band = #ofp_meter_band_experimenter{type = experimenter, rate = Rate,
                                                burst_size = BurstSize,
                                                experimenter = Experimenter}
    end,
    decode_bands(Rest, [Band | Bands]).

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
decode_body(packet_in, Binary) ->
    <<BufferIdInt:32, TotalLen:16, ReasonInt:8,
      TableId:8, Cookie:64/bits, Tail/bytes>> = Binary,
    MatchLength = size(Binary) - (?PACKET_IN_SIZE - ?MATCH_SIZE)
        - 2 - TotalLen + ?OFP_HEADER_SIZE,
    <<MatchBin:MatchLength/bytes, 0:16, Payload/bytes>> = Tail,
    BufferId = get_id(buffer, BufferIdInt),
    Reason = ofp_v4_enum:to_atom(packet_in_reason, ReasonInt),
    Match = decode_match(MatchBin),
    <<Data:TotalLen/bytes>> = Payload,
    #ofp_packet_in{buffer_id = BufferId, reason = Reason,
                   table_id = TableId, cookie = Cookie,
                   match = Match, data = Data};
decode_body(flow_removed, Binary) ->
    MatchLength = size(Binary) - ?FLOW_REMOVED_SIZE + ?MATCH_SIZE
        + ?OFP_HEADER_SIZE,
    <<Cookie:8/bytes, Priority:16, ReasonInt:8,
      TableId:8, Sec:32, NSec:32, Idle:16,
      Hard:16, PCount:64, BCount:64,
      MatchBin:MatchLength/bytes>> = Binary,
    Reason = ofp_v4_enum:to_atom(flow_removed_reason, ReasonInt),
    Match = decode_match(MatchBin),
    #ofp_flow_removed{cookie = Cookie, priority = Priority,
                      reason = Reason, table_id = TableId, duration_sec = Sec,
                      duration_nsec = NSec, idle_timeout = Idle,
                      hard_timeout = Hard, packet_count = PCount,
                      byte_count = BCount, match = Match};
decode_body(port_status, Binary) ->
    <<ReasonInt:8, 0:56, PortBin:?PORT_SIZE/bytes>> = Binary,
    Reason = ofp_v4_enum:to_atom(port_reason, ReasonInt),
    Port = decode_port(PortBin),
    #ofp_port_status{reason = Reason, desc = Port};

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

decode_body(barrier_request, _) ->
    #ofp_barrier_request{};
decode_body(barrier_reply, _) ->
    #ofp_barrier_reply{};
decode_body(queue_get_config_request, Binary) ->
    <<PortInt:32, 0:32>> = Binary,
    Port = get_id(port_no, PortInt),
    #ofp_queue_get_config_request{port = Port};
decode_body(queue_get_config_reply, Binary) ->
    QueuesLength = size(Binary) - ?QUEUE_GET_CONFIG_REPLY_SIZE
        + ?OFP_HEADER_SIZE,
    <<PortInt:32, 0:32, QueuesBin:QueuesLength/bytes>> = Binary,
    Port = get_id(port_no, PortInt),
    Queues = decode_queues(QueuesBin),
    #ofp_queue_get_config_reply{port = Port,
                                queues = Queues};
decode_body(role_request, Binary) ->
    <<RoleInt:32, 0:32, Gen:64>> = Binary,
    Role = ofp_v4_enum:to_atom(controller_role, RoleInt),
    #ofp_role_request{role = Role, generation_id = Gen};
decode_body(role_reply, Binary) ->
    <<RoleInt:32, 0:32, Gen:64>> = Binary,
    Role = ofp_v4_enum:to_atom(controller_role, RoleInt),
    #ofp_role_reply{role = Role, generation_id = Gen};

decode_body(get_async_request, _) ->
    #ofp_get_async_request{};
decode_body(get_async_reply, Binary) ->
    {PacketInMask, PortStatusMask, FlowRemovedMask} = decode_async_masks(Binary),
    #ofp_get_async_reply{packet_in_mask = PacketInMask,
                         port_status_mask = PortStatusMask,
                         flow_removed_mask = FlowRemovedMask};
decode_body(set_async, Binary) ->
    {PacketInMask, PortStatusMask, FlowRemovedMask} = decode_async_masks(Binary),
    #ofp_set_async{packet_in_mask = PacketInMask,
                   port_status_mask = PortStatusMask,
                   flow_removed_mask = FlowRemovedMask};
decode_body(meter_mod, Binary) ->
    <<CommandInt:16, FlagsInt:16, MeterIdInt:32, BandsBin/bytes>> = Binary,
    Command = get_id(meter_mod_command, CommandInt),
    Flags = get_id(meter_flag, FlagsInt),
    MeterId = get_id(meter_id, MeterIdInt),
    Bands = decode_bands(BandsBin),
    #ofp_meter_mod{command = Command, flags = Flags, meter_id = MeterId,
                   bands = Bands}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

binary_to_flags(Type, Binary) ->
    ofp_utils:binary_to_flags(ofp_v4_enum, Type, Binary).

get_id(Enum, Value) ->
    ofp_utils:get_enum_name(ofp_v4_enum, Enum, Value).
