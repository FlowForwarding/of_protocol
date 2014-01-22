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
%% @doc OpenFlow Protocol 1.4 (5) decoding implementation.
%% @private
-module(ofp_v5_decode).

-export([do/1]).

-include("of_protocol.hrl").
-include("ofp_v5.hrl").

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

%% @doc Actual decoding of the message.
-spec do(Binary :: binary()) -> {ok, ofp_message(), binary()}.
do(Binary) when ?OFP_HEADER_SIZE > byte_size(Binary) ->
    {error, binary_too_small};
do(Binary) ->
    <<Version:8, TypeInt:8, Length:16, XID:32, Binary2/bytes>> = Binary,
    case Length > byte_size(Binary) of
        true ->
            {error, binary_too_small};
        false ->
            BodyLength = Length - 8,
            <<BodyBin:BodyLength/bytes, Rest/bytes >> = Binary2,
            Type = ofp_v5_enum:to_atom(type, TypeInt),
            Body = decode_body(Type, BodyBin),
            {ok, #ofp_message{version = Version, type = Type,
                              xid = XID, body = Body}, Rest}
    end.

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
    <<FieldsBin:FieldsBinLength/bytes, _:Padding>> = PadFieldsBin,
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
    Class = ofp_v5_enum:to_atom(oxm_class, ClassInt),
    Field = ofp_v5_enum:to_atom(oxm_ofb_match_fields, FieldInt),
    HasMask = (HasMaskInt =:= 1),
    case Class of
        openflow_basic ->
            BitLength = ofp_v5_map:tlv_length(Field);
        _ ->
            BitLength = Length * 4
    end,
    case HasMask of
        false ->
            <<Value:Length/bytes, Rest/bytes>> = Binary,
            TLV = #ofp_field{value = ofp_utils:uncut_bits(Value, BitLength)};
        true ->
            Length2 = (Length div 2),
            <<Value:Length2/bytes, Mask:Length2/bytes,
              Rest/bytes>> = Binary,
            TLV = #ofp_field{value = ofp_utils:uncut_bits(Value, BitLength),
                             mask = ofp_utils:uncut_bits(Mask, BitLength)}
    end,
    {TLV#ofp_field{class = Class,
                   name = Field,
                   has_mask = HasMask}, Rest}.

%% @doc Decode port structure.
decode_port(Binary) ->
    <<PortNoInt:32, _Length:16, _:16, HWAddr:6/bytes, _:16, NameBin:16/bytes,
      ConfigBin:4/bytes, StateBin:4/bytes, PropertiesBin/binary>> = Binary,
    PortNo = get_id(port_no, PortNoInt),
    Name = ofp_utils:strip_string(NameBin),
    Config = binary_to_flags(port_config, ConfigBin),
    State = binary_to_flags(port_state, StateBin),
    Properties = decode_port_properties(PropertiesBin),
    #ofp_port{port_no = PortNo, hw_addr = HWAddr, name = Name,
              config = Config, state = State, properties = Properties}.

decode_port_list(Binary) ->
    decode_port_list(Binary, []).

decode_port_list(<<>>, Ports) ->
    lists:reverse(Ports);
decode_port_list(Binary, Ports) ->
    <<_PortNo:32, Length:16, _/binary>> = Binary,
    <<PortBin:Length/bytes, Rest/bytes>> = Binary,
    Port = decode_port(PortBin),
    decode_port_list(Rest, [Port | Ports]).

decode_port_properties(<<>>) ->
    [];
decode_port_properties(<<TypeInt:16, Length:16, Rest/binary>>) ->
    Type = ofp_v5_enum:to_atom(port_desc_properties, TypeInt),
    RemainingLength = Length - 4,
    PaddingLength = (Length + 7) div 8 * 8 - Length,
    <<PropBin:RemainingLength/bytes, _:PaddingLength/bytes, Tail/binary>> = Rest,
    [decode_port_property(Type, PropBin) | decode_port_properties(Tail)].

decode_port_property(ethernet, Binary) ->
    <<_:32, CurrBin:4/bytes, AdvertisedBin:4/bytes, SupportedBin:4/bytes,
      PeerBin:4/bytes, CurrSpeed:32, MaxSpeed:32>> = Binary,
    Curr = binary_to_flags(port_features, CurrBin),
    Advertised = binary_to_flags(port_features, AdvertisedBin),
    Supported = binary_to_flags(port_features, SupportedBin),
    Peer = binary_to_flags(port_features, PeerBin),
    #ofp_port_desc_prop_ethernet{
       curr = Curr, advertised = Advertised, supported = Supported,
       peer = Peer, curr_speed = CurrSpeed, max_speed = MaxSpeed};
decode_port_property(optical, Binary) ->
    <<_:32, SupportedBin:4/bytes, TxMinFreqLmda:32, TxMaxFreqLmda:32, TxGridFreqLmda:32,
      RxMinFreqLmda:32, RxMaxFreqLmda:32, RxGridFreqLmda:32,
      TxPwrMin:16, TxPwrMax:16>> = Binary,
    Supported = binary_to_flags(optical_port_features, SupportedBin),
    #ofp_port_desc_prop_optical{
       supported = Supported,
       tx_min_freq_lmda = TxMinFreqLmda,
       tx_max_freq_lmda = TxMaxFreqLmda,
       tx_grid_freq_lmda = TxGridFreqLmda,
       rx_min_freq_lmda = RxMinFreqLmda,
       rx_max_freq_lmda = RxMaxFreqLmda,
       rx_grid_freq_lmda = RxGridFreqLmda,
       tx_pwr_min = TxPwrMin,
       tx_pwr_max = TxPwrMax
      };
decode_port_property(experimenter, Binary) ->
    <<Experimenter:32, ExpType:32, Data/binary>> = Binary,
    #ofp_port_desc_prop_experimenter{
       experimenter = Experimenter,
       exp_type = ExpType,
       data = Data}.

%% @doc Decode queues
decode_queues(Binary) ->
    decode_queues(Binary, []).

decode_queues(<<>>, Queues) ->
    lists:reverse(Queues);
decode_queues(Binary, Queues) ->
    <<QueueId:32, Port:32, Length:16, _Pad:48, Data/bytes>> = Binary,
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
    <<TypeInt:16, Length:16, _Pad:32,
      Data/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(queue_properties, TypeInt),
    case Type of
        min_rate ->
            <<Rate:16, _Pad:48, Rest/bytes>> = Data,
            Property = #ofp_queue_prop_min_rate{rate = Rate};
        max_rate ->
            <<Rate:16, _Pad:48, Rest/bytes>> = Data,
            Property = #ofp_queue_prop_max_rate{rate = Rate};
        experimenter ->
            DataLength = Length - ?QUEUE_PROP_EXPERIMENTER_SIZE,
            <<Experimenter:32, _Pad:32, ExpData:DataLength/bytes,
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
    Type = ofp_v5_enum:to_atom(meter_band_type, TypeInt),
    case Type of
        drop ->
            <<_Pad:32, Rest/bytes>> = Data,
            Band = #ofp_meter_band_drop{type = drop, rate = Rate,
                                        burst_size = BurstSize};
        dscp_remark ->
            <<PrecLevel:8, _Pad:24, Rest/bytes>> = Data,
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

%% @doc Decode actions
-spec decode_actions(binary()) -> [ofp_action()].
decode_actions(Binary) ->
    decode_actions(Binary, []).

-spec decode_actions(binary(), [ofp_action()]) -> [ofp_action()].
decode_actions(<<>>, Actions) ->
    lists:reverse(Actions);
decode_actions(Binary, Actions) ->
    <<TypeInt:16, Length:16, Data/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(action_type, TypeInt),
    case Type of
        output ->
            <<PortInt:32, MaxLenInt:16,
              _Pad:48, Rest/bytes>> = Data,
            Port = get_id(port_no, PortInt),
            MaxLen = get_id(max_len, MaxLenInt),
            Action = #ofp_action_output{port = Port, max_len = MaxLen};
        group ->
            <<GroupInt:32, Rest/bytes>> = Data,
            Group = get_id(group, GroupInt),
            Action = #ofp_action_group{group_id = Group};
        set_queue ->
            <<QueueInt:32, Rest/bytes>> = Data,
            Queue = get_id(queue, QueueInt),
            Action = #ofp_action_set_queue{queue_id = Queue};
        set_mpls_ttl ->
            <<TTL:8, _Pad:24, Rest/bytes>> = Data,
            Action = #ofp_action_set_mpls_ttl{mpls_ttl = TTL};
        dec_mpls_ttl ->
            <<_Pad:32, Rest/bytes>> = Data,
            Action = #ofp_action_dec_mpls_ttl{};
        set_nw_ttl ->
            <<TTL:8, _Pad:24, Rest/bytes>> = Data,
            Action = #ofp_action_set_nw_ttl{nw_ttl = TTL};
        dec_nw_ttl ->
            <<_Pad:32, Rest/bytes>> = Data,
            Action = #ofp_action_dec_nw_ttl{};
        copy_ttl_out ->
            <<_Pad:32, Rest/bytes>> = Data,
            Action = #ofp_action_copy_ttl_out{};
        copy_ttl_in ->
            <<_Pad:32, Rest/bytes>> = Data,
            Action = #ofp_action_copy_ttl_in{};
        push_vlan ->
            <<EtherType:16, _Pad:16, Rest/bytes>> = Data,
            Action = #ofp_action_push_vlan{ethertype = EtherType};
        pop_vlan ->
            <<_Pad:32, Rest/bytes>> = Data,
            Action = #ofp_action_pop_vlan{};
        push_mpls ->
            <<EtherType:16, _Pad:16, Rest/bytes>> = Data,
            Action = #ofp_action_push_mpls{ethertype = EtherType};
        pop_mpls ->
            <<EtherType:16, _Pad:16, Rest/bytes>> = Data,
            Action = #ofp_action_pop_mpls{ethertype = EtherType};
        push_pbb ->
            <<EtherType:16, _Pad:16, Rest/bytes>> = Data,
            Action = #ofp_action_push_pbb{ethertype = EtherType};
        pop_pbb ->
            <<_Pad:32, Rest/bytes>> = Data,
            Action = #ofp_action_pop_pbb{};
        set_field ->
            FieldLength = Length - 4,
            <<FieldBin:FieldLength/bytes, Rest/bytes>> = Data,
            {Field, _Pad} = decode_match_field(FieldBin),
            Action = #ofp_action_set_field{field = Field};
        experimenter ->
            DataLength = Length - ?ACTION_EXPERIMENTER_SIZE,
            <<Experimenter:32, ExpData:DataLength/bytes, Rest/bytes>> = Data,
            Action = #ofp_action_experimenter{experimenter = Experimenter,
                                              data = ExpData}
    end,
    decode_actions(Rest, [Action | Actions]).

%% @doc Decode instructions
-spec decode_instructions(binary()) -> [ofp_instruction()].
decode_instructions(Binary) ->
    decode_instructions(Binary, []).

-spec decode_instructions(binary(), [ofp_instruction()]) ->
                                 [ofp_instruction()].
decode_instructions(<<>>, Instructions) ->
    lists:reverse(Instructions);
decode_instructions(Binary, Instructions) ->
    <<TypeInt:16, Length:16, Data/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(instruction_type, TypeInt),
    case Type of
        goto_table ->
            <<Table:8, _Pad:24, Rest/bytes>> = Data,
            Instruction = #ofp_instruction_goto_table{table_id = Table};
        write_metadata ->
            <<_Pad:32, Metadata:8/bytes, MetaMask:8/bytes,
              Rest/bytes>> = Data,
            Instruction = #ofp_instruction_write_metadata{
                             metadata = Metadata,
                             metadata_mask = MetaMask};
        write_actions ->
            ActionsLength = Length - ?INSTRUCTION_WRITE_ACTIONS_SIZE,
            <<_Pad:32, ActionsBin:ActionsLength/bytes,
              Rest/bytes>> = Data,
            Actions = decode_actions(ActionsBin),
            Instruction = #ofp_instruction_write_actions{actions = Actions};
        apply_actions ->
            ActionsLength = Length - ?INSTRUCTION_APPLY_ACTIONS_SIZE,
            <<_Pad:32, ActionsBin:ActionsLength/bytes,
              Rest/bytes>> = Data,
            Actions = decode_actions(ActionsBin),
            Instruction = #ofp_instruction_apply_actions{actions = Actions};
        clear_actions ->
            <<_Pad:32, Rest/bytes>> = Data,
            Instruction = #ofp_instruction_clear_actions{};
        meter ->
            <<MeterIdInt:32, Rest/bytes>> = Data,
            MeterId = get_id(meter_id, MeterIdInt),
            Instruction = #ofp_instruction_meter{meter_id = MeterId};
        experimenter ->
            DataLength = Length - ?INSTRUCTION_EXPERIMENTER_SIZE,
            <<Experimenter:32, ExpData:DataLength/bytes, Rest/bytes>> = Data,
            Instruction = #ofp_instruction_experimenter{
                             experimenter = Experimenter, data = ExpData}
    end,
    decode_instructions(Rest, [Instruction | Instructions]).

%% @doc Decode buckets
decode_buckets(Binary) ->
    decode_buckets(Binary, []).

decode_buckets(<<>>, Buckets) ->
    lists:reverse(Buckets);
decode_buckets(Binary, Buckets) ->
    <<Length:16, Weight:16, Port:32, Group:32,
      _Pad:32, Data/bytes>> = Binary,
    ActionsLength = Length - ?BUCKET_SIZE,
    <<ActionsBin:ActionsLength/bytes, Rest/bytes>> = Data,
    Actions = decode_actions(ActionsBin),
    Bucket = #ofp_bucket{weight = Weight, watch_port = Port, watch_group = Group,
                         actions = Actions},
    decode_buckets(Rest, [Bucket | Buckets]).

decode_flow_stats_list(Binary) ->
    decode_flow_stats_list(Binary, []).

decode_flow_stats_list(<<>>, FlowStatsList) ->
    lists:reverse(FlowStatsList);
decode_flow_stats_list(Binary, FlowStatsList) ->
    <<Length:16, _/bytes>> = Binary,
    <<FlowStatsBin:Length/bytes, Rest/bytes>> = Binary,
    FlowStats = decode_flow_stats(FlowStatsBin),
    decode_flow_stats_list(Rest, [FlowStats | FlowStatsList]).

decode_flow_stats(Binary) ->
    <<_:16, Table:8, _:8, Sec:32, NSec:32, Priority:16, Idle:16, Hard:16,
      FlagsBin:2/bytes, _:32, Cookie:8/bytes, PCount:64, BCount:64,
      Data/bytes>> = Binary,
    <<_:16, MatchLength:16, _/bytes>> = Data,
    MatchLengthPad = MatchLength + ofp_utils:padding(MatchLength, 8),
    <<MatchBin:MatchLengthPad/bytes, InstrsBin/bytes>> = Data,
    Match = decode_match(MatchBin),
    Instrs = decode_instructions(InstrsBin),
    Flags = binary_to_flags(flow_mod_flags, FlagsBin),
    #ofp_flow_stats{table_id = Table, duration_sec = Sec, duration_nsec = NSec,
                    priority = Priority, idle_timeout = Idle,
                    hard_timeout = Hard, flags = Flags, cookie = Cookie,
                    packet_count = PCount, byte_count = BCount,
                    match = Match, instructions = Instrs}.

decode_table_stats(Binary) ->
    <<TableInt:8, _Pad:24, ACount:32, LCount:64, MCount:64>> = Binary,
    Table = get_id(table, TableInt),
    #ofp_table_stats{table_id = Table, active_count = ACount,
                     lookup_count = LCount, matched_count = MCount}.

%% A.3.5.5 Table Features ------------------------------------------------------

table_features(<<>>, TableFeatures) ->
    lists:reverse(TableFeatures);
table_features(Binary, TableFeatures) ->
    <<Length:16, _/bytes>> = Binary,
    PropsLength = Length - ?OFP_TABLE_FEATURES_SIZE,
    <<_:16, TableIdInt:8, _:40, Name:?OFP_MAX_TABLE_NAME_LEN/bytes,
      MetadataMatch:8/bytes, MetadataWrite:8/bytes, CapabilitiesBin:4/bytes, MaxEntries:32,
      PropertiesBin:PropsLength/bytes, Rest/bytes>> = Binary,
    TableId = get_id(table, TableIdInt),
    StrippedName = ofp_utils:strip_string(Name),
    Capabilities = binary_to_flags(table_config, CapabilitiesBin),
    Properties = table_feature_prop(PropertiesBin, []),
    TableFeature = #ofp_table_features{table_id = TableId,
                                       name = StrippedName,
                                       metadata_match = MetadataMatch,
                                       metadata_write = MetadataWrite,
                                       capabilities = Capabilities,
                                       max_entries = MaxEntries,
                                       properties = Properties},
    table_features(Rest, [TableFeature | TableFeatures]).

table_feature_prop(<<>>, Properties) ->
    lists:reverse(Properties);
table_feature_prop(Binary, Properties) ->
    <<TypeInt:16, Length:16, _/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(table_feature_prop_type, TypeInt),
    IdsLength = Length - 4,
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<_:16, _:16, IdsBin:IdsLength/bytes, _:Padding, Rest/bytes>> = Binary,
    Property = case Type of
                   instructions ->
                       table_feature_prop_instructions(IdsBin, []);
                   instructions_miss ->
                       table_feature_prop_instructions_miss(IdsBin, []);
                   next_tables ->
                       table_feature_prop_next_tables(IdsBin, []);
                   next_tables_miss ->
                       table_feature_prop_next_tables_miss(IdsBin, []);
                   write_actions ->
                       table_feature_prop_write_actions(IdsBin, []);
                   write_actions_miss ->
                       table_feature_prop_write_actions_miss(IdsBin, []);
                   apply_actions ->
                       table_feature_prop_apply_actions(IdsBin, []);
                   apply_actions_miss ->
                       table_feature_prop_apply_actions_miss(IdsBin, []);
                   match ->
                       table_feature_prop_match(IdsBin, []);
                   wildcards ->
                       table_feature_prop_wildcards(IdsBin, []);
                   write_setfield ->
                       table_feature_prop_write_setfield(IdsBin, []);
                   write_setfield_miss ->
                       table_feature_prop_write_setfield_miss(IdsBin, []);
                   apply_setfield ->
                       table_feature_prop_apply_setfield(IdsBin, []);
                   apply_setfield_miss ->
                       table_feature_prop_apply_setfield_miss(IdsBin, []);
                   experimenter ->
                       table_feature_prop_experimenter(IdsBin);
                   experimenter_miss ->
                       table_feature_prop_experimenter_miss(IdsBin)
               end,
    table_feature_prop(Rest, [Property | Properties]).

table_feature_prop_instructions(<<>>, Ids) ->
    #ofp_table_feature_prop_instructions{instruction_ids = lists:reverse(Ids)};
table_feature_prop_instructions(Binary, Ids) ->
    <<TypeInt:16, _:16, _/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(instruction_type, TypeInt),
    case Type of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_instructions(Rest, [{experimenter, Id} | Ids]);
        _ ->
            <<_:16, _:16, Rest/bytes>> = Binary,
            table_feature_prop_instructions(Rest, [Type | Ids])
    end.

table_feature_prop_instructions_miss(<<>>, Ids) ->
    #ofp_table_feature_prop_instructions_miss{
       instruction_ids = lists:reverse(Ids)};
table_feature_prop_instructions_miss(Binary, Ids) ->
    <<TypeInt:16, _:16, _/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(instruction_type, TypeInt),
    case Type of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_instructions_miss(Rest,
                                                 [{experimenter, Id} | Ids]);
        _ ->
            <<_:16, _:16, Rest/bytes>> = Binary,
            table_feature_prop_instructions_miss(Rest, [Type | Ids])
    end.

table_feature_prop_next_tables(<<>>, Ids) ->
    #ofp_table_feature_prop_next_tables{next_table_ids = lists:reverse(Ids)};
table_feature_prop_next_tables(<<Id:8, Rest/bytes>>, Ids) ->
    table_feature_prop_next_tables(Rest, [Id | Ids]).

table_feature_prop_next_tables_miss(<<>>, Ids) ->
    #ofp_table_feature_prop_next_tables_miss{
       next_table_ids = lists:reverse(Ids)};
table_feature_prop_next_tables_miss(<<Id:8, Rest/bytes>>, Ids) ->
    table_feature_prop_next_tables_miss(Rest, [Id | Ids]).

table_feature_prop_write_actions(<<>>, Ids) ->
    #ofp_table_feature_prop_write_actions{action_ids = lists:reverse(Ids)};
table_feature_prop_write_actions(Binary, Ids) ->
    <<TypeInt:16, _:16, _/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(action_type, TypeInt),
    case Type of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_write_actions(Rest, [{experimenter, Id} | Ids]);
        _ ->
            <<_:16, _:16, Rest/bytes>> = Binary,
            table_feature_prop_write_actions(Rest, [Type | Ids])
    end.

table_feature_prop_write_actions_miss(<<>>, Ids) ->
    #ofp_table_feature_prop_write_actions_miss{action_ids = lists:reverse(Ids)};
table_feature_prop_write_actions_miss(Binary, Ids) ->
    <<TypeInt:16, _:16, _/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(action_type, TypeInt),
    case Type of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_write_actions_miss(Rest,
                                                  [{experimenter, Id} | Ids]);
        _ ->
            <<_:16, _:16, Rest/bytes>> = Binary,
            table_feature_prop_write_actions_miss(Rest, [Type | Ids])
    end.

table_feature_prop_apply_actions(<<>>, Ids) ->
    #ofp_table_feature_prop_apply_actions{action_ids = lists:reverse(Ids)};
table_feature_prop_apply_actions(Binary, Ids) ->
    <<TypeInt:16, _:16, _/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(action_type, TypeInt),
    case Type of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_apply_actions(Rest, [{experimenter, Id} | Ids]);
        _ ->
            <<_:16, _:16, Rest/bytes>> = Binary,
            table_feature_prop_apply_actions(Rest, [Type | Ids])
    end.

table_feature_prop_apply_actions_miss(<<>>, Ids) ->
    #ofp_table_feature_prop_apply_actions_miss{action_ids = lists:reverse(Ids)};
table_feature_prop_apply_actions_miss(Binary, Ids) ->
    <<TypeInt:16, _:16, _/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(action_type, TypeInt),
    case Type of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_apply_actions_miss(Rest,
                                                  [{experimenter, Id} | Ids]);
        _ ->
            <<_:16, _:16, Rest/bytes>> = Binary,
            table_feature_prop_apply_actions_miss(Rest, [Type | Ids])
    end.

table_feature_prop_match(<<>>, Ids) ->
    #ofp_table_feature_prop_match{oxm_ids = lists:reverse(Ids)};
table_feature_prop_match(Binary, Ids) ->
    <<ClassInt:16, _:16, _/bytes>> = Binary,
    Class = ofp_v5_enum:to_atom(oxm_class, ClassInt),
    case Class of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_match(Rest, [{experimenter, Id} | Ids]);
        openflow_basic ->
            <<_:16, IdInt:7, _:1, _:8, Rest/bytes>> = Binary,
            Id = ofp_v5_enum:to_atom(oxm_ofb_match_fields, IdInt),
            table_feature_prop_match(Rest, [Id | Ids])
    end.

table_feature_prop_wildcards(<<>>, Ids) ->
    #ofp_table_feature_prop_wildcards{oxm_ids = lists:reverse(Ids)};
table_feature_prop_wildcards(Binary, Ids) ->
    <<ClassInt:16, _:16, _/bytes>> = Binary,
    Class = ofp_v5_enum:to_atom(oxm_class, ClassInt),
    case Class of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_wildcards(Rest, [{experimenter, Id} | Ids]);
        openflow_basic ->
            <<_:16, IdInt:7, _:1, _:8, Rest/bytes>> = Binary,
            Id = ofp_v5_enum:to_atom(oxm_ofb_match_fields, IdInt),
            table_feature_prop_wildcards(Rest, [Id | Ids])
    end.

table_feature_prop_write_setfield(<<>>, Ids) ->
    #ofp_table_feature_prop_write_setfield{oxm_ids = lists:reverse(Ids)};
table_feature_prop_write_setfield(Binary, Ids) ->
    <<ClassInt:16, _:16, _/bytes>> = Binary,
    Class = ofp_v5_enum:to_atom(oxm_class, ClassInt),
    case Class of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_write_setfield(Rest, [{experimenter, Id} | Ids]);
        openflow_basic ->
            <<_:16, IdInt:7, _:1, _:8, Rest/bytes>> = Binary,
            Id = ofp_v5_enum:to_atom(oxm_ofb_match_fields, IdInt),
            table_feature_prop_write_setfield(Rest, [Id | Ids])
    end.

table_feature_prop_write_setfield_miss(<<>>, Ids) ->
    #ofp_table_feature_prop_write_setfield_miss{oxm_ids = lists:reverse(Ids)};
table_feature_prop_write_setfield_miss(Binary, Ids) ->
    <<ClassInt:16, _:16, _/bytes>> = Binary,
    Class = ofp_v5_enum:to_atom(oxm_class, ClassInt),
    case Class of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_write_setfield_miss(
              Rest, [{experimenter, Id} | Ids]);
        openflow_basic ->
            <<_:16, IdInt:7, _:1, _:8, Rest/bytes>> = Binary,
            Id = ofp_v5_enum:to_atom(oxm_ofb_match_fields, IdInt),
            table_feature_prop_write_setfield_miss(Rest, [Id | Ids])
    end.

table_feature_prop_apply_setfield(<<>>, Ids) ->
    #ofp_table_feature_prop_apply_setfield{oxm_ids = lists:reverse(Ids)};
table_feature_prop_apply_setfield(Binary, Ids) ->
    <<ClassInt:16, _:16, _/bytes>> = Binary,
    Class = ofp_v5_enum:to_atom(oxm_class, ClassInt),
    case Class of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_apply_setfield(Rest, [{experimenter, Id} | Ids]);
        openflow_basic ->
            <<_:16, IdInt:7, _:1, _:8, Rest/bytes>> = Binary,
            Id = ofp_v5_enum:to_atom(oxm_ofb_match_fields, IdInt),
            table_feature_prop_apply_setfield(Rest, [Id | Ids])
    end.

table_feature_prop_apply_setfield_miss(<<>>, Ids) ->
    #ofp_table_feature_prop_apply_setfield_miss{oxm_ids = lists:reverse(Ids)};
table_feature_prop_apply_setfield_miss(Binary, Ids) ->
    <<ClassInt:16, _:16, _/bytes>> = Binary,
    Class = ofp_v5_enum:to_atom(oxm_class, ClassInt),
    case Class of
        experimenter ->
            <<_:16, _:16, Id:32, Rest/bytes>> = Binary,
            table_feature_prop_apply_setfield_miss(
              Rest, [{experimenter, Id} | Ids]);
        openflow_basic ->
            <<_:16, IdInt:7, _:1, _:8, Rest/bytes>> = Binary,
            Id = ofp_v5_enum:to_atom(oxm_ofb_match_fields, IdInt),
            table_feature_prop_apply_setfield_miss(Rest, [Id | Ids])
    end.

table_feature_prop_experimenter(Binary) ->
    <<Experimenter:32, ExpType:32, Data/bytes>> = Binary,
    #ofp_table_feature_prop_experimenter{experimenter = Experimenter,
                                         exp_type = ExpType,
                                         data = Data}.

table_feature_prop_experimenter_miss(Binary) ->
    <<Experimenter:32, ExpType:32, Data/bytes>> = Binary,
    #ofp_table_feature_prop_experimenter_miss{experimenter = Experimenter,
                                              exp_type = ExpType,
                                              data = Data}.

%% ---

decode_port_stats(<<>>) ->
    [];
decode_port_stats(Binary) ->
    <<EntryLength:16, _/binary>> = Binary,
    <<ThisEntry:EntryLength/bytes, Tail/binary>> = Binary,
    <<_:16, _:16, PortInt:32, DSec:32, DNSec:32,
      RXPackets:64, TXPackets:64, RXBytes:64, TXBytes:64,
      RXDropped:64, TXDropped:64, RXErrors:64, TXErrors:64,
      PropertiesBin/binary>> = ThisEntry,

    Port = get_id(port_no, PortInt),
    [#ofp_port_stats{port_no = Port,
                     duration_sec = DSec, duration_nsec = DNSec,
                     rx_packets = RXPackets, tx_packets = TXPackets,
                     rx_bytes = RXBytes, tx_bytes = TXBytes,
                     rx_dropped = RXDropped, tx_dropped = TXDropped,
                     rx_errors = RXErrors, tx_errors = TXErrors,
                     properties = decode_port_stats_properties(PropertiesBin)}
     | decode_port_stats(Tail)].

decode_port_stats_properties(PropertiesBin) ->
    lists:map(
      fun({ethernet, PropBin}) ->
              <<_Pad:32, FrameErr:64, OverErr:64, CRCErr:64, Collisions:64>> = PropBin,
              #ofp_port_stats_prop_ethernet{
                 rx_frame_err = FrameErr, rx_over_err = OverErr,
                 rx_crc_err = CRCErr, collisions = Collisions};
         ({optical, PropBin}) ->
              <<_Pad:32, FlagsBin:4/bytes,
                TxFreqLmda:32, TxOffset:32, TxGridSpan:32,
                RxFreqLmda:32, RxOffset:32, RxGridSpan:32,
                TxPwr:16, RxPwr:16, BiasCurrent:16, Temperature:16>> = PropBin,
              Flags = binary_to_flags(port_stats_optical_flag, FlagsBin),
              #ofp_port_stats_prop_optical{
                 flags = Flags,
                 tx_freq_lmda = TxFreqLmda,
                 tx_offset = TxOffset,
                 tx_grid_span = TxGridSpan,
                 rx_freq_lmda = RxFreqLmda,
                 rx_offset = RxOffset,
                 rx_grid_span = RxGridSpan,
                 tx_pwr = TxPwr,
                 rx_pwr = RxPwr,
                 bias_current = BiasCurrent,
                 temperature = Temperature};
         ({experimenter, PropBin}) ->
              <<Experimenter:32, ExpType:32, Data/binary>> = PropBin,
              #ofp_port_stats_prop_experimenter{
                 experimenter = Experimenter,
                 exp_type = ExpType,
                 data = Data}
      end, extract_properties(port_stats_prop_type, PropertiesBin)).

decode_queue_stats(<<>>) ->
    [];
decode_queue_stats(<<EntryLength:16, _/binary>> = Binary) ->
    <<ThisEntry:EntryLength/bytes, Tail/binary>> = Binary,
    <<_:16, _:48, PortInt:32, QueueInt:32, Bytes:64,
      Packets:64, Errors:64, DSec:32, DNSec:32,
      PropertiesBin/binary>> = ThisEntry,
    Port = get_id(port_no, PortInt),
    Queue = get_id(queue, QueueInt),
    [#ofp_queue_stats{port_no = Port, queue_id = Queue, tx_bytes = Bytes,
                     tx_packets = Packets, tx_errors = Errors,
                     duration_sec = DSec, duration_nsec = DNSec,
                     properties = decode_queue_stats_properties(PropertiesBin)}
     | decode_queue_stats(Tail)].

decode_queue_stats_properties(PropertiesBin) ->
    lists:map(fun({experimenter, PropBin}) ->
                      <<Experimenter:32, ExpType:32, Data/binary>> = PropBin,
                      #ofp_queue_stats_prop_experimenter{
                         experimenter = Experimenter,
                         exp_type = ExpType,
                         data = Data}
              end, extract_properties(queue_stats_prop_type, PropertiesBin)).

decode_group_stats(Binary) ->
    <<_:16, _Pad:16, GroupInt:32, RefCount:32,
      _Pad:32, PCount:64, BCount:64, DSec:32, DNSec:32,
      BucketsBin/bytes>> = Binary,
    Group = get_id(group, GroupInt),
    Buckets = decode_bucket_counters(BucketsBin),
    #ofp_group_stats{group_id = Group, ref_count = RefCount,
                     packet_count = PCount, byte_count = BCount,
                     duration_sec = DSec, duration_nsec = DNSec,
                     bucket_stats = Buckets}.

decode_group_stats_list(Binary) ->
    decode_group_stats_list(Binary, []).

decode_group_stats_list(<<>>, StatsList) ->
    lists:reverse(StatsList);
decode_group_stats_list(Binary, StatsList) ->
    <<Length:16, _/bytes>> = Binary,
    <<StatsBin:Length/bytes, Rest/bytes>> = Binary,
    Stats = decode_group_stats(StatsBin),
    decode_group_stats_list(Rest, [Stats | StatsList]).

decode_bucket_counters(Binary) ->
    decode_bucket_counters(Binary, []).

decode_bucket_counters(<<>>, Buckets) ->
    lists:reverse(Buckets);
decode_bucket_counters(<<PCount:64, BCount:64, Rest/bytes>>,
                       Buckets) ->
    decode_bucket_counters(Rest,
                           [#ofp_bucket_counter{packet_count = PCount,
                                                byte_count = BCount} | Buckets]).

decode_group_desc_stats(Binary) ->
    <<_:16, TypeInt:8, _Pad:8,
      GroupInt:32, BucketsBin/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(group_type, TypeInt),
    Group = get_id(group_desc, GroupInt),
    Buckets = decode_buckets(BucketsBin),
    #ofp_group_desc_stats{type = Type, group_id = Group,
                          buckets = Buckets}.

decode_group_desc_stats_list(Binary) ->
    decode_group_desc_stats_list(Binary, []).

decode_group_desc_stats_list(<<>>, StatsList) ->
    lists:reverse(StatsList);
decode_group_desc_stats_list(Binary, StatsList) ->
    <<Length:16, _/bytes>> = Binary,
    <<StatsBin:Length/bytes, Rest/bytes>> = Binary,
    Stats = decode_group_desc_stats(StatsBin),
    decode_group_desc_stats_list(Rest, [Stats | StatsList]).

decode_meter_stats_list(Binary) ->
    decode_meter_stats_list(Binary, []).

decode_meter_stats_list(<<>>, MeterStats) ->
    lists:reverse(MeterStats);
decode_meter_stats_list(Binary, MeterStats) ->
    {M, Rest} = decode_meter_stats(Binary),
    decode_meter_stats_list(Rest, [M | MeterStats]).

decode_meter_stats(Binary) ->
    <<MeterIdBin:32, Length:16, _Pad:48, FlowCount:32, PacketInCount:64,
      ByteInCount:64, DSec:32, DNSec:32, Rest/bytes>> = Binary,
    MeterId = get_id(meter_id, MeterIdBin),
    case Rest of
        <<>> ->
            Rest2 = Rest,
            BandStats = [];
        _ ->        
            BandStatsLength = Length - ?METER_STATS_SIZE,
            <<BandStatsBin:BandStatsLength/bytes, Rest2/bytes>> = Rest,
            BandStats = decode_band_stats(BandStatsBin)
    end,
    {#ofp_meter_stats{meter_id = MeterId, flow_count = FlowCount,
                      packet_in_count = PacketInCount,
                      byte_in_count = ByteInCount, duration_sec = DSec,
                      duration_nsec = DNSec, band_stats = BandStats},
     Rest2}.

decode_band_stats(Binary) ->
    decode_band_stats(Binary, []).

decode_band_stats(<<>>, Stats) ->
    lists:reverse(Stats);
decode_band_stats(Binary, Stats) ->
    <<PacketBandCount:64, ByteBandCount:64, Rest/bytes>> = Binary,
    S = #ofp_meter_band_stats{packet_band_count = PacketBandCount,
                              byte_band_count = ByteBandCount},
    decode_band_stats(Rest, [S | Stats]).

decode_meter_config_list(Binary) ->
    decode_meter_config_list(Binary, []).

decode_meter_config_list(<<>>, MeterConfigs) ->
    lists:reverse(MeterConfigs);
decode_meter_config_list(Binary, MeterConfigs) ->
    <<Length:16, FlagsBin:16/bits, MeterIdInt:32, Rest/bytes>> = Binary,
    case Rest of
        <<>> ->
            Rest2 = Rest,
            Bands = [];
        _ ->        
            BandsLength = Length - ?METER_CONFIG_SIZE,
            <<BandsBin:BandsLength/bytes, Rest2/bytes>> = Rest,
            Bands = decode_bands(BandsBin)
    end,
    Flags = binary_to_flags(meter_flag, FlagsBin),
    MeterId = get_id(meter_id, MeterIdInt),
    MeterConfig = #ofp_meter_config{flags = Flags, meter_id = MeterId,
                                    bands = Bands},
    decode_meter_config_list(Rest2, [MeterConfig | MeterConfigs]).

decode_table_desc(<<>>) ->
    [];
decode_table_desc(<<TotalLength:16, TableIdInt:8, _Pad:8, ConfigBin:32/bits,
                    Rest/binary>>) ->
    PropertiesLength = TotalLength - 8,
    <<PropertiesBin:PropertiesLength/bytes, Tail/binary>> = Rest,

    TableId = get_id(table, TableIdInt),
    Config = binary_to_flags(table_config, ConfigBin),
    Properties = decode_table_mod_properties(PropertiesBin),

    [#ofp_table_desc{table_id = TableId, config = Config, properties = Properties}
     | decode_table_desc(Tail)].

decode_queue_desc(<<>>) ->
    [];
decode_queue_desc(<<PortInt:32, QueueInt:32, TotalLength:16, _Pad:48, Rest/binary>>) ->
    PropertiesLength = TotalLength - 16,
    <<PropertiesBin:PropertiesLength/bytes, Tail/binary>> = Rest,

    Port = get_id(port_no, PortInt),
    Queue = get_id(queue, QueueInt),
    Properties = decode_queue_desc_properties(PropertiesBin),

    [#ofp_queue_desc{port_no = Port, queue_id = Queue, properties = Properties}
     | decode_queue_desc(Tail)].

decode_bitmap(_, Index, _, Acc) when Index >= 32 ->
    Acc;
decode_bitmap(Int, Index, Base, Acc) when Int band (1 bsl Index) == 0 ->
    decode_bitmap(Int, Index + 1, Base, Acc);
decode_bitmap(Int, Index, Base, Acc) ->
    decode_bitmap(Int, Index + 1, Base, [Base + Index|Acc]).

decode_bitmap(<<>>, _, Acc) ->
    Acc;
decode_bitmap(<<Int:32, Rest/bytes>>, Base, Acc) ->
    Acc2 = decode_bitmap(Int, 0, Base, Acc),
    decode_bitmap(Rest, Base + 32, Acc2).

decode_bitmap(Binary) ->
    decode_bitmap(Binary, 0, []).

decode_hello_elements(<<>>, Acc) ->
    Acc;
decode_hello_elements(Binary, Acc) ->
    <<TypeInt:16, Length:16, Rest1/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(hello_elem, TypeInt),
    DataLength = Length - 4,
    <<Data:DataLength/bytes, Rest2/bytes>> = Rest1,
    Acc2 = case Type of
               versionbitmap ->
                   [{versionbitmap, decode_bitmap(Data)}|Acc];
               _ ->
                   %% ignore unknown types
                   Acc
           end,
    decode_hello_elements(Rest2, Acc2).

decode_hello_elements(Binary) ->
    decode_hello_elements(Binary, []).

%% @doc Actual decoding of the messages
-spec decode_body(atom(), binary()) -> ofp_message().
decode_body(hello, Binary) ->
    #ofp_hello{elements = decode_hello_elements(Binary)};
decode_body(error, Binary) ->
    <<TypeInt:16, More/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(error_type, TypeInt),
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
            Code = ofp_v5_enum:to_atom(Type, CodeInt),
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
    <<DataPathID:16, DataPathMac:48/bits, NBuffers:32,
      NTables:8, AuxId:8, _Pad:16, CapaBin:32/bits, _Pad:32>> = Binary,
    Capabilities = binary_to_flags(capabilities, CapaBin),
    #ofp_features_reply{datapath_mac = DataPathMac,
                        datapath_id = DataPathID, n_buffers = NBuffers,
                        n_tables = NTables, auxiliary_id = AuxId,
                        capabilities = Capabilities};
decode_body(get_config_request, _) ->
    #ofp_get_config_request{};
decode_body(get_config_reply, Binary) ->
    <<FlagsBin:16/bits, MissInt:16>> = Binary,
    Flags = binary_to_flags(config_flags, FlagsBin),
    Miss = get_id(miss_send_len, MissInt),
    #ofp_get_config_reply{flags = Flags,
                          miss_send_len = Miss};
decode_body(set_config, Binary) ->
    <<FlagsBin:16/bits, MissInt:16>> = Binary,
    Flags = binary_to_flags(config_flags, FlagsBin),
    Miss = get_id(miss_send_len, MissInt),
    #ofp_set_config{flags = Flags, miss_send_len = Miss};
decode_body(packet_in, Binary) ->
    <<BufferIdInt:32, TotalLen:16, ReasonInt:8,
      TableId:8, Cookie:64/bits, Tail/bytes>> = Binary,
    MatchLength = size(Binary) - (?PACKET_IN_SIZE - ?MATCH_SIZE)
        - 2 - TotalLen + ?OFP_HEADER_SIZE,
    <<MatchBin:MatchLength/bytes, _Pad:16, Payload/bytes>> = Tail,
    BufferId = get_id(buffer_id, BufferIdInt),
    Reason = ofp_v5_enum:to_atom(packet_in_reason, ReasonInt),
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
    Reason = ofp_v5_enum:to_atom(flow_removed_reason, ReasonInt),
    Match = decode_match(MatchBin),
    #ofp_flow_removed{cookie = Cookie, priority = Priority,
                      reason = Reason, table_id = TableId, duration_sec = Sec,
                      duration_nsec = NSec, idle_timeout = Idle,
                      hard_timeout = Hard, packet_count = PCount,
                      byte_count = BCount, match = Match};
decode_body(port_status, Binary) ->
    <<ReasonInt:8, _Pad:56, PortBin/bytes>> = Binary,
    Reason = ofp_v5_enum:to_atom(port_reason, ReasonInt),
    Port = decode_port(PortBin),
    #ofp_port_status{reason = Reason, desc = Port};
decode_body(packet_out, Binary) ->
    <<BufferIdInt:32, PortInt:32, ActionsLength:16,
      _Pad:48, Binary2/bytes>> = Binary,
    DataLength = size(Binary) - ?PACKET_OUT_SIZE + ?OFP_HEADER_SIZE
        - ActionsLength,
    <<ActionsBin:ActionsLength/bytes, Data:DataLength/bytes>> = Binary2,
    BufferId = get_id(buffer_id, BufferIdInt),
    Port = get_id(port_no, PortInt),
    Actions = decode_actions(ActionsBin),
    #ofp_packet_out{buffer_id = BufferId, in_port = Port,
                    actions = Actions, data = Data};
decode_body(flow_mod, Binary) ->
    <<Cookie:8/bytes, CookieMask:8/bytes, TableInt:8, CommandInt:8,
      Idle:16, Hard:16, Priority:16, BufferIdInt:32, OutPortInt:32,
      OutGroupInt:32, FlagsBin:2/bytes, _Pad:16, Data/bytes>> = Binary,
    Table = get_id(table, TableInt),
    BufferId = get_id(buffer_id, BufferIdInt),
    Command = ofp_v5_enum:to_atom(flow_mod_command, CommandInt),
    OutPort = get_id(port_no, OutPortInt),
    OutGroup = get_id(group, OutGroupInt),
    Flags = binary_to_flags(flow_mod_flags, FlagsBin),
    <<_:16, MatchLength:16, _/bytes>> = Data,
    Padding = ofp_utils:padding(MatchLength, 8),
    MatchLengthPad = MatchLength + Padding,
    <<MatchBin:MatchLengthPad/bytes, InstrBin/bytes>> = Data,
    Match = decode_match(MatchBin),
    Instructions = decode_instructions(InstrBin),
    #ofp_flow_mod{cookie = Cookie, cookie_mask = CookieMask,
                  table_id = Table, command = Command, idle_timeout = Idle,
                  hard_timeout = Hard, priority = Priority, buffer_id = BufferId,
                  out_port = OutPort, out_group = OutGroup, flags = Flags,
                  match = Match, instructions = Instructions};
decode_body(group_mod, Binary) ->
    BucketsLength = size(Binary) - ?GROUP_MOD_SIZE + ?OFP_HEADER_SIZE,
    <<CommandInt:16, TypeInt:8, _Pad:8,
      GroupInt:32, BucketsBin:BucketsLength/bytes>> = Binary,
    Command = ofp_v5_enum:to_atom(group_mod_command, CommandInt),
    Type = ofp_v5_enum:to_atom(group_type, TypeInt),
    Group = get_id(group, GroupInt),
    Buckets = decode_buckets(BucketsBin),
    #ofp_group_mod{command = Command, type = Type,
                   group_id = Group, buckets = Buckets};
decode_body(port_mod, Binary) ->
    <<PortInt:32, _Pad:32, Addr:6/bytes,
      _Pad:16, ConfigBin:4/bytes, MaskBin:4/bytes,
      PropertiesBin/binary>> = Binary,
    Port = get_id(port_no, PortInt),
    Config = binary_to_flags(port_config, ConfigBin),
    Mask = binary_to_flags(port_config, MaskBin),
    #ofp_port_mod{port_no = Port, hw_addr = Addr,
                  config = Config, mask = Mask,
                  properties = decode_port_mod_properties(PropertiesBin)};
decode_body(table_mod, Binary) ->
    <<TableInt:8, _Pad:24, ConfigBin:4/bytes, PropertiesBin/binary>> = Binary,
    Table = get_id(table, TableInt),
    Config = binary_to_flags(table_config, ConfigBin),
    #ofp_table_mod{table_id = Table, config = Config,
                   properties = decode_table_mod_properties(PropertiesBin)};
decode_body(multipart_request, Binary) ->
    <<TypeInt:16, FlagsBin:16/bits, _Pad:32, Data/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(multipart_type, TypeInt),
    Flags = binary_to_flags(multipart_request_flags, FlagsBin),
    case Type of
        desc ->
            #ofp_desc_request{flags = Flags};
        flow_stats ->
            MatchLength = size(Binary) - (?FLOW_STATS_REQUEST_SIZE - ?MATCH_SIZE) + ?OFP_HEADER_SIZE,
            <<TableInt:8, _Pad:24, PortInt:32,
              GroupInt:32, _Pad:32, Cookie:8/bytes,
              CookieMask:8/bytes, MatchBin:MatchLength/bytes>> = Data,
            Table = get_id(table, TableInt),
            Port = get_id(port_no, PortInt),
            Group = get_id(group, GroupInt),
            Match = decode_match(MatchBin),
            #ofp_flow_stats_request{flags = Flags,
                                    table_id = Table, out_port = Port,
                                    out_group = Group, cookie = Cookie,
                                    cookie_mask = CookieMask, match = Match};
        aggregate_stats ->
            MatchLength = size(Binary) - (?AGGREGATE_STATS_REQUEST_SIZE - ?MATCH_SIZE) + ?OFP_HEADER_SIZE,
            <<TableInt:8, _Pad:24, PortInt:32,
              GroupInt:32, _Pad:32, Cookie:8/bytes,
              CookieMask:8/bytes, MatchBin:MatchLength/bytes>> = Data,
            Table = get_id(table, TableInt),
            Port = get_id(port_no, PortInt),
            Group = get_id(group, GroupInt),
            Match = decode_match(MatchBin),
            #ofp_aggregate_stats_request{flags = Flags,
                                         table_id = Table, out_port = Port,
                                         out_group = Group, cookie = Cookie,
                                         cookie_mask = CookieMask, match = Match};
        table_stats ->
            #ofp_table_stats_request{flags = Flags};
        table_features ->
            Features = table_features(Data, []),
            #ofp_table_features_request{flags = Flags,
                                        body = Features};
        port_desc ->
            #ofp_port_desc_request{flags = Flags};
        port_stats ->
            <<PortInt:32, _Pad:32>> = Data,
            Port = get_id(port_no, PortInt),
            #ofp_port_stats_request{flags = Flags,
                                    port_no = Port};
        queue_stats ->
            <<PortInt:32, QueueInt:32>> = Data,
            Port = get_id(port_no, PortInt),
            Queue = get_id(queue, QueueInt),
            #ofp_queue_stats_request{flags = Flags, port_no = Port,
                                     queue_id = Queue};
        group_stats ->
            <<GroupInt:32, _Pad:32>> = Data,
            Group = get_id(group, GroupInt),
            #ofp_group_stats_request{flags = Flags,
                                     group_id = Group};
        group_desc ->
            #ofp_group_desc_request{flags = Flags};
        group_features ->
            #ofp_group_features_request{flags = Flags};
        meter_stats ->
            <<MeterIdBin:32, _Pad:32>> = Data,
            MeterId = get_id(meter_id, MeterIdBin),
            #ofp_meter_stats_request{flags = Flags, meter_id = MeterId};
        meter_config ->
            <<MeterIdBin:32, _Pad:32>> = Data,
            MeterId = get_id(meter_id, MeterIdBin),
            #ofp_meter_config_request{flags = Flags, meter_id = MeterId};
        meter_features ->
            #ofp_meter_features_request{flags = Flags};
        table_desc ->
            #ofp_table_desc_request{flags = Flags};
        queue_desc ->
            <<PortInt:32, QueueInt:32>> = Data,
            Port = get_id(port_no, PortInt),
            Queue = get_id(queue, QueueInt),
            #ofp_queue_desc_request{flags = Flags, port_no = Port,
                                    queue_id = Queue};
        flow_monitor ->
            <<MId:32, PortInt:32, GroupInt:32, MonFlagsBin:16/bits, 
              TableInt:8, CmdInt:8, MatchBin/bytes>> = Data,
            Port = get_id(port_no, PortInt),
            Group = get_id(group, GroupInt),
            MonFlags = binary_to_flags(flow_monitor_flags, MonFlagsBin),
            TableId = get_id(table, TableInt),
            Cmd = ofp_v5_enum:to_atom(flow_monitor_command, CmdInt),
            Match = decode_match(MatchBin),
            #ofp_flow_monitor_request{flags = Flags,
                                      monitor_id = MId,
                                      out_port = Port,
                                      out_group = Group,
                                      monitor_flags = MonFlags,
                                      table_id = TableId,
                                      command = Cmd,
                                      match = Match};
        experimenter ->
            DataLength = size(Binary) - ?EXPERIMENTER_STATS_REQUEST_SIZE + ?OFP_HEADER_SIZE,
            <<Experimenter:32, ExpType:32,
              ExpData:DataLength/bytes>> = Data,
            #ofp_experimenter_request{flags = Flags,
                                      experimenter = Experimenter,
                                      exp_type = ExpType, data = ExpData}
    end;
decode_body(multipart_reply, Binary) ->
    <<TypeInt:16, FlagsBin:16/bits, _Pad:32, Data/bytes>> = Binary,
    Type = ofp_v5_enum:to_atom(multipart_type, TypeInt),
    Flags = binary_to_flags(multipart_reply_flags, FlagsBin),
    case Type of
        desc ->
            <<MFR:?DESC_STR_LEN/bytes, HW:?DESC_STR_LEN/bytes,
              SW:?DESC_STR_LEN/bytes, Serial:?SERIAL_NUM_LEN/bytes,
              DP:?DESC_STR_LEN/bytes>> = Data,
            #ofp_desc_reply{flags = Flags,
                            mfr_desc = ofp_utils:strip_string(MFR),
                            hw_desc = ofp_utils:strip_string(HW),
                            sw_desc = ofp_utils:strip_string(SW),
                            serial_num = ofp_utils:strip_string(Serial),
                            dp_desc = ofp_utils:strip_string(DP)};
        flow_stats ->
            StatsLength = size(Binary) - ?FLOW_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = decode_flow_stats_list(StatsBin),
            #ofp_flow_stats_reply{flags = Flags,
                                  body = Stats};
        aggregate_stats ->
            <<PCount:64, BCount:64, FCount:32,
              _Pad:32>> = Data,
            #ofp_aggregate_stats_reply{flags = Flags,
                                       packet_count = PCount,
                                       byte_count = BCount,
                                       flow_count = FCount};
        table_stats ->
            StatsLength = size(Binary) - ?TABLE_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = [decode_table_stats(TStats)
                     || TStats <- ofp_utils:split_binaries(StatsBin,
                                                           ?TABLE_STATS_SIZE)],
            #ofp_table_stats_reply{flags = Flags,
                                   body = Stats};
        table_features ->
            Features = table_features(Data, []),
            #ofp_table_features_reply{flags = Flags,
                                      body = Features};
        port_desc ->
            Ports = decode_port_list(Data),
            #ofp_port_desc_reply{flags = Flags, body = Ports};
        port_stats ->
            StatsLength = size(Binary) - ?PORT_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = decode_port_stats(StatsBin),
            #ofp_port_stats_reply{flags = Flags, body = Stats};
        queue_stats ->
            StatsLength = size(Binary) - ?QUEUE_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = decode_queue_stats(StatsBin),
            #ofp_queue_stats_reply{flags = Flags, body = Stats};
        group_stats ->
            StatsLength = size(Binary) - ?GROUP_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = decode_group_stats_list(StatsBin),
            #ofp_group_stats_reply{flags = Flags, body = Stats};
        group_desc ->
            StatsLength = size(Binary) - ?GROUP_DESC_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = decode_group_desc_stats_list(StatsBin),
            #ofp_group_desc_reply{flags = Flags, body = Stats};
        group_features ->
            <<TypesBin:4/bytes, CapabilitiesBin:4/bytes, Max1:32,
              Max2:32, Max3:32, Max4:32,
              Actions1Bin:4/bytes, Actions2Bin:4/bytes, Actions3Bin:4/bytes,
              Actions4Bin:4/bytes>> = Data,
            Types = binary_to_flags(group_type, TypesBin),
            Capabilities = binary_to_flags(group_capabilities, CapabilitiesBin),
            Actions1 = binary_to_flags(action_type, Actions1Bin),
            Actions2 = binary_to_flags(action_type, Actions2Bin),
            Actions3 = binary_to_flags(action_type, Actions3Bin),
            Actions4 = binary_to_flags(action_type, Actions4Bin),
            #ofp_group_features_reply{flags = Flags, types = Types,
                                      capabilities = Capabilities,
                                      max_groups = {Max1, Max2, Max3, Max4},
                                      actions = {Actions1, Actions2,
                                                 Actions3, Actions4}};
        meter_stats ->
            MeterStats = decode_meter_stats_list(Data),
            #ofp_meter_stats_reply{flags = Flags, body = MeterStats};
        meter_config ->
            Config = decode_meter_config_list(Data),
            #ofp_meter_config_reply{flags = Flags, body = Config};
        meter_features ->
            <<MaxMeter:32, BandTypesBin:32/bits, CapabilitiesBin:32/bits,
              MaxBands:8, MaxColor:8, _Pad:16>> = Data,
            BandTypes = binary_to_flags(meter_band_type, BandTypesBin),
            Capabilities = binary_to_flags(meter_flag, CapabilitiesBin),
            #ofp_meter_features_reply{flags = Flags, max_meter = MaxMeter,
                                      band_types = BandTypes,
                                      capabilities = Capabilities, 
                                      max_bands = MaxBands,
                                      max_color = MaxColor};
        table_desc ->
            Tables = decode_table_desc(Data),
            #ofp_table_desc_reply{flags = Flags, tables = Tables};
        queue_desc ->
            Queues = decode_queue_desc(Data),
            #ofp_queue_desc_reply{flags = Flags, queues = Queues};
        flow_monitor ->
            Updates = case size(Data) of
                          0 ->
                              %% Empty utdate list
                              [];
                          _ ->
                              decode_flow_updates(Data)
                      end,
            #ofp_flow_monitor_reply{flags = Flags,
                                    updates = Updates};
        experimenter ->
            DataLength = size(Binary) - ?EXPERIMENTER_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<Experimenter:32, ExpType:32,
              ExpData:DataLength/bytes>> = Data,
            #ofp_experimenter_reply{flags = Flags, experimenter = Experimenter,
                                    exp_type = ExpType, data = ExpData}
    end;
decode_body(barrier_request, _) ->
    #ofp_barrier_request{};
decode_body(barrier_reply, _) ->
    #ofp_barrier_reply{};
decode_body(queue_get_config_request, Binary) ->
    <<PortInt:32, _Pad:32>> = Binary,
    Port = get_id(port_no, PortInt),
    #ofp_queue_get_config_request{port = Port};
decode_body(queue_get_config_reply, Binary) ->
    QueuesLength = size(Binary) - ?QUEUE_GET_CONFIG_REPLY_SIZE
        + ?OFP_HEADER_SIZE,
    <<PortInt:32, _Pad:32, QueuesBin:QueuesLength/bytes>> = Binary,
    Port = get_id(port_no, PortInt),
    Queues = decode_queues(QueuesBin),
    #ofp_queue_get_config_reply{port = Port,
                                queues = Queues};
decode_body(role_request, Binary) ->
    <<RoleInt:32, _Pad:32, Gen:64>> = Binary,
    Role = ofp_v5_enum:to_atom(controller_role, RoleInt),
    #ofp_role_request{role = Role, generation_id = Gen};
decode_body(role_reply, Binary) ->
    <<RoleInt:32, _Pad:32, Gen:64>> = Binary,
    Role = ofp_v5_enum:to_atom(controller_role, RoleInt),
    #ofp_role_reply{role = Role, generation_id = Gen};
decode_body(role_status, Binary) ->
    <<RoleInt:32, ReasonInt:8, _Pad:24, Gen:64, PropertiesBin/binary>> = Binary,
    Role = ofp_v5_enum:to_atom(controller_role, RoleInt),
    Reason = ofp_v5_enum:to_atom(controller_role_reason, ReasonInt),
    #ofp_role_status{role = Role, reason = Reason, generation_id = Gen,
                     properties = decode_role_status_properties(PropertiesBin)};

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
    <<CommandInt:16, FlagsBin:2/bytes, MeterIdInt:32, BandsBin/bytes>> = Binary,
    Command = get_id(meter_mod_command, CommandInt),
    Flags = binary_to_flags(meter_flag, FlagsBin),
    MeterId = get_id(meter_id, MeterIdInt),
    Bands = decode_bands(BandsBin),
    #ofp_meter_mod{command = Command, flags = Flags, meter_id = MeterId,
                   bands = Bands}.

%% This function can be used to extract properties from a binary.
%% It assumes that each property begins with:
%%
%%    uint16_t type;
%%    uint16_t length;
%%
%% where length does not include the padding necessary to make the
%% length of each property a multiple of 8.
%%
%% It converts the type to an atom using ofp_v5_enum:to_atom, and
%% returns a list of the type [{Type :: atom(), Data :: binary()}].
%% The Data binary does not contain the type and length fields.
extract_properties(Enum, <<TypeInt:16, Length:16, Rest/binary>>) ->
    Type = ofp_v5_enum:to_atom(Enum, TypeInt),
    Padding = (Length + 7) div 8 * 8 - Length,
    PropLength = Length - 4,
    <<This:PropLength/binary, _Padded:Padding/binary, Tail/binary>> = Rest,
    [{Type, This} | extract_properties(Enum, Tail)];
extract_properties(_Enum, <<>>) ->
    [].

decode_role_status_properties(Bin) ->
    lists:map(
      fun({experimenter, PropBin}) ->
              <<Experimenter:32, ExpType:32, Data/binary>> = PropBin,
              #ofp_role_prop_experimenter{experimenter = Experimenter,
                                          exp_type = ExpType,
                                          data = Data}
      end, extract_properties(role_prop_type, Bin)).

decode_table_mod_properties(Bin) ->
    lists:map(
      fun({eviction, PropBin}) ->
              <<FlagsBin:4/bytes>> = PropBin,
              #ofp_table_mod_prop_eviction{
                 flags = binary_to_flags(table_mod_prop_eviction_flag, FlagsBin)};
         ({vacancy, PropBin}) ->
              <<VacancyDown:8, VacancyUp:8, Vacancy:8, _Pad:8>> = PropBin,
              #ofp_table_mod_prop_vacancy{
                 vacancy_down = VacancyDown,
                 vacancy_up = VacancyUp,
                 vacancy = Vacancy};
         ({experimenter, PropBin}) ->
              <<Experimenter:32, ExpType:32, Data/binary>> = PropBin,
              #ofp_table_mod_prop_experimenter{
                 experimenter = Experimenter,
                 exp_type = ExpType,
                 data = Data}
      end, extract_properties(table_mod_prop_type, Bin)).

decode_port_mod_properties(Bin) ->
    lists:map(
      fun({ethernet, PropBin}) ->
              <<AdvertiseBin:4/bytes>> = PropBin,
              Advertise = binary_to_flags(port_features, AdvertiseBin),
              #ofp_port_mod_prop_ethernet{advertise = Advertise};
         ({optical, PropBin}) ->
              <<ConfigureBin:4/bytes, FreqLmda:32, FlOffset:32/signed,
                GridSpan:32, TxPwr:32>> = PropBin,
              Configure = binary_to_flags(optical_port_features, ConfigureBin),
              #ofp_port_mod_prop_optical{configure = Configure, freq_lmda = FreqLmda,
                                         fl_offset = FlOffset, grid_span = GridSpan,
                                         tx_pwr = TxPwr};
         ({experimenter, PropBin}) ->
              <<Experimenter:32, ExpType:32, Data/binary>> = PropBin,
              #ofp_port_mod_prop_experimenter{
                 experimenter = Experimenter,
                 exp_type = ExpType,
                 data = Data}
      end, extract_properties(port_mod_prop_type, Bin)).

decode_queue_desc_properties(Bin) ->
    lists:map(
      fun({min_rate, PropBin}) ->
              <<Rate:16, _Pad:16>> = PropBin,
              #ofp_queue_desc_prop_min_rate{rate = Rate};
         ({max_rate, PropBin}) ->
              <<Rate:16, _Pad:16>> = PropBin,
              #ofp_queue_desc_prop_max_rate{rate = Rate};
         ({experimenter, PropBin}) ->
              <<Experimenter:32, ExpType:32, Data/binary>> = PropBin,
              #ofp_queue_desc_prop_experimenter{
                 experimenter = Experimenter,
                 exp_type = ExpType,
                 data = Data}
      end, extract_properties(queue_desc_prop_type, Bin)).

decode_flow_updates(Data) ->
    <<Length:16, EventInt:16, Bin/bytes>> = Data,
    Event = ofp_v5_enum:to_atom(flow_update_event, EventInt),
    case Event of
        Event when Event =:= paused;
                   Event =:= resumed ->
            decode_flow_update(Event, Bin);
        _ ->
            L = case Length of  %% Size of remainder of this update 
                    8 -> 4;
                    _ -> Length - 12  %% 32 + Match + Instr is not the real size of the payload 
                end,
            case size(Bin) of
                L ->
                    [decode_flow_update(Event, Bin)];
                _ ->
                    <<RecBin:L/bytes, Remainder/binary>> = Bin,
                    [decode_flow_update(Event, RecBin) |
                     decode_flow_updates(Remainder)]
            end
    end.

decode_flow_update(abbrev, <<Xid:32>>) ->
    #ofp_flow_update_abbrev{event = abbrev,
                            xid = Xid};
decode_flow_update(Event, _Data) when Event =:= paused;
                                              Event =:= resumed ->
    #ofp_flow_update_paused{event = Event};
decode_flow_update(Event, Data) ->
    <<TableInt:8, ReasonInt:8, ITO:16, HTO:16, Priority:16, 
      0:32, Cookie:8/bytes, MatchAndInstr/binary>> = Data, 
    TableId = get_id(table, TableInt),
    Reason = ofp_v5_enum:to_atom(flow_removed_reason, ReasonInt),
    {Match, InstrBin} = decode_match_with_remainder(MatchAndInstr),
    Instructions = 
        case InstrBin of
            no_value -> [];
            _ -> decode_instructions(InstrBin)
        end,
    #ofp_flow_update_full{event = Event,
                          table_id = TableId,
                          reason = Reason,
                          idle_timeout = ITO,
                          hard_timeout = HTO,
                          priority = Priority,
                          cookie = Cookie,
                          match = Match,
                          instructions = Instructions}.

decode_match_with_remainder(Binary) ->
    <<1:16, NoPadLength:16, More/binary>> = Binary,
    FieldsBinLength = (NoPadLength - 4),
    Padding = ((NoPadLength + 7) div 8) * 8 - NoPadLength,
    {FieldsBin, Remainder} = 
        case byte_size(More) - FieldsBinLength - Padding of
            0 ->
                <<FBin:FieldsBinLength/bytes, _:Padding/bytes>> = More,
                {FBin, no_value};
            _ ->
                <<FBin:FieldsBinLength/bytes, _:Padding/bytes, R/binary>> = More,
                {FBin, R}
        end,
    Fields = decode_match_fields(FieldsBin),
    {#ofp_match{fields = Fields}, Remainder}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

binary_to_flags(Type, Binary) ->
    ofp_utils:binary_to_flags(ofp_v5_enum, Type, Binary).

get_id(Enum, Value) ->
    ofp_utils:get_enum_name(ofp_v5_enum, Enum, Value).
