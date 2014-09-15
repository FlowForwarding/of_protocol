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

-export([do/1,
         encode_struct/1,
         encode_body/1]).

-include("of_protocol.hrl").
-include("ofp_v4.hrl").

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

%% @doc Actual encoding of the message.
-spec do(Message :: ofp_message()) -> binary().
do(#ofp_message{version = ?VERSION, xid = Xid, body = Body}) ->
    BodyBin = encode_body(Body),
    TypeInt = type_int(Body),
    Length = ?OFP_HEADER_SIZE + size(BodyBin),
    <<?VERSION:8, TypeInt:8, Length:16, Xid:32, BodyBin/bytes>>.

%%------------------------------------------------------------------------------
%% Encode functions
%%------------------------------------------------------------------------------

%% Structures ------------------------------------------------------------------

encode_struct(#ofp_match{fields = Fields}) ->
    FieldsBin = encode_list(Fields),
    FieldsLength = size(FieldsBin),
    Length = FieldsLength + ?MATCH_SIZE - 4,
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<1:16, Length:16, FieldsBin/bytes, 0:Padding>>;
encode_struct(#ofp_field{class = Class, name = Field, has_mask = HasMask,
                         value = Value, mask = Mask}) ->
    ClassInt = ofp_v4_enum:to_int(oxm_class, Class),
    {FieldInt, BitLength, WireBitLength} = case Class of
        openflow_basic ->
            {ofp_v4_enum:to_int(oxm_ofb_match_fields, Field),
             ofp_v4_map:tlv_length(Field),
             ofp_v4_map:tlv_wire_length(Field)};
        _ ->
            Len = bit_size(Value),
            {Field, Len, Len}
    end,
    WireBitLength2 = (WireBitLength + 7) div 8 * 8,
    Value2 = ofp_utils:cut_bits(Value, BitLength, WireBitLength2),
    case HasMask of
        true ->
            HasMaskInt = 1,
            Mask2 = ofp_utils:cut_bits(Mask, BitLength, WireBitLength2),
            Rest = <<Value2/bytes, Mask2/bytes>>,
            Len2 = byte_size(Value2) * 2;
        false ->
            HasMaskInt = 0,
            Rest = <<Value2/bytes>>,
            Len2 = byte_size(Value2)
    end,
    <<ClassInt:16, FieldInt:7, HasMaskInt:1, Len2:8, Rest/bytes>>;

encode_struct(#ofp_port{port_no = PortNo, hw_addr = HWAddr, name = Name,
                        config = Config, state = State, curr = Curr,
                        advertised = Advertised, supported = Supported,
                        peer = Peer, curr_speed = CurrSpeed,
                        max_speed = MaxSpeed}) ->
    PortNoInt = get_id(port_no, PortNo),
    NameBin = ofp_utils:encode_string(Name, ?OFP_MAX_PORT_NAME_LEN),
    ConfigBin = flags_to_binary(port_config, Config, 4),
    StateBin = flags_to_binary(port_state, State, 4),
    CurrBin = flags_to_binary(port_features, Curr, 4),
    AdvertisedBin = flags_to_binary(port_features, Advertised, 4),
    SupportedBin = flags_to_binary(port_features, Supported, 4),
    PeerBin = flags_to_binary(port_features, Peer, 4),
    <<PortNoInt:32, 0:32, HWAddr:?OFP_ETH_ALEN/bytes, 0:16,
      NameBin:?OFP_MAX_PORT_NAME_LEN/bytes,
      ConfigBin:4/bytes, StateBin:4/bytes, CurrBin:4/bytes,
      AdvertisedBin:4/bytes, SupportedBin:4/bytes,
      PeerBin:4/bytes, CurrSpeed:32, MaxSpeed:32>>;

encode_struct(#ofp_port_v6{ port_no = PortNo, hw_addr = _HWAddr, name = Name,
                            config = Config, state = State,
                            properties = Properties }) ->
    PortNoInt = get_id(port_no, PortNo),
    NameBin = ofp_utils:encode_string(Name, ?OFP_MAX_PORT_NAME_LEN),
    ConfigBin = flags_to_binary(port_config, Config, 4),
    StateBin = flags_to_binary(port_state, State, 4),
    PropertiesBin = list_to_binary(lists:map(fun encode_struct/1, Properties)),
    Length = 40 + byte_size(PropertiesBin),
    HardCOdeHWAddr = <<8,0,39,255,136,50>>,
    <<PortNoInt:32, Length:16, 0:16, HardCOdeHWAddr:?OFP_ETH_ALEN/bytes, 0:16,
      NameBin:?OFP_MAX_PORT_NAME_LEN/bytes,
      ConfigBin:4/bytes, StateBin:4/bytes,
      PropertiesBin/binary>>;

encode_struct(#ofp_port_desc_prop_optical_transport{type             = Type,
                                                    port_signal_type = PortSigType,
                                                    reserved         = Reserved,
                                                    features         = Features}) ->
    TypeInt = ofp_v4_enum:to_int(port_desc_properties, Type),
    BinFeatures = list_to_binary(lists:map(fun encode_struct/1, Features)),
    Length = 8 + byte_size(BinFeatures),
    PortSigTypeId = ofp_v4_enum:to_int(otport_signal_type,PortSigType),
    <<TypeInt:16, Length:16, PortSigTypeId:8, Reserved:8, 0:16, BinFeatures/binary>>;

encode_struct(#ofp_port_optical_transport_application_code{ oic_type = OICType,
                                                            app_code = AppCode }) ->
    FeatureTypeInt = ofp_v4_enum:to_int(port_optical_transport_feature_type,opt_interface_class),
    OICTypeInt     = ofp_v4_enum:to_int(optical_interface_class,OICType),
    AppCodeBin     = ofp_utils:encode_string(AppCode, 15),
    Length         = 16 + (15 * 8),
    <<FeatureTypeInt:16, Length:16, OICTypeInt:8, AppCodeBin:15/bytes>>;

encode_struct(#ofp_port_optical_transport_layer_stack{ value = Values }) ->
    FeatureTypeInt = ofp_v4_enum:to_int(port_optical_transport_feature_type,layer_stack),
    ValuesBin      = list_to_binary(lists:map(fun encode_struct/1, Values)),
    Length         = 8 + byte_size(ValuesBin),
    <<FeatureTypeInt:16, Length:16, 0:32, ValuesBin/binary>>;
    
encode_struct(#ofp_port_optical_transport_layer_entry{  layer_class = LayerClass,
                                                        signal_type = SignalType,
                                                        adaptation  = Adaptation }) ->
    LayerClassInt = ofp_v4_enum:to_int(port_optical_transport_layer_class,LayerClass),
    SignalTypeID = 
        case LayerClass of 
            port    -> ofp_v4_enum:to_int(otport_signal_type, SignalType);
            och     -> ofp_v4_enum:to_int(och_signal_type,    SignalType);
            odu     -> ofp_v4_enum:to_int(odu_signal_type,    SignalType);
            oduclt  -> ofp_v4_enum:to_int(oduclt_signal_type, SignalType)
        end,
    AdaptationInt = ofp_v4_enum:to_int(adaptations_type,Adaptation),
    <<LayerClassInt:8, SignalTypeID:8, AdaptationInt:8, 0:40>>;

encode_struct(#ofp_packet_queue{queue_id = Queue, port_no = Port,
                                properties = Props}) ->
    PropsBin = encode_list(Props),
    Length = ?PACKET_QUEUE_SIZE + size(PropsBin),
    <<Queue:32, Port:32, Length:16, 0:48, PropsBin/bytes>>;

encode_struct(#ofp_queue_prop_min_rate{rate = Rate}) ->
    PropertyInt = ofp_v4_enum:to_int(queue_properties, min_rate),
    <<PropertyInt:16, ?QUEUE_PROP_MIN_RATE_SIZE:16, 0:32, Rate:16, 0:48>>;
encode_struct(#ofp_queue_prop_max_rate{rate = Rate}) ->
    PropertyInt = ofp_v4_enum:to_int(queue_properties, max_rate),
    <<PropertyInt:16, ?QUEUE_PROP_MAX_RATE_SIZE:16, 0:32, Rate:16, 0:48>>;
encode_struct(#ofp_queue_prop_experimenter{experimenter = Experimenter,
                                           data = Data}) ->
    Length = ?QUEUE_PROP_EXPERIMENTER_SIZE + byte_size(Data),
    PropertyInt = ofp_v4_enum:to_int(queue_properties, experimenter),
    <<PropertyInt:16, Length:16, 0:32, Experimenter:32, 0:32, Data/bytes>>;

encode_struct(#ofp_meter_band_drop{type = drop, rate = Rate,
                                   burst_size = BurstSize}) ->
    TypeInt = ofp_v4_enum:to_int(meter_band_type, drop),
    <<TypeInt:16, ?METER_BAND_SIZE:16, Rate:32, BurstSize:32, 0:32>>;
encode_struct(#ofp_meter_band_dscp_remark{type = dscp_remark, rate = Rate,
                                          burst_size = BurstSize,
                                          prec_level = PrecLevel}) ->
    TypeInt = ofp_v4_enum:to_int(meter_band_type, dscp_remark),
    <<TypeInt:16, ?METER_BAND_SIZE:16, Rate:32, BurstSize:32,
      PrecLevel:8, 0:24>>;
encode_struct(#ofp_meter_band_experimenter{type = experimenter, rate = Rate,
                                           burst_size = BurstSize,
                                           experimenter = Experimenter}) ->
    TypeInt = ofp_v4_enum:to_int(meter_band_type, experimenter),
    <<TypeInt:16, ?METER_BAND_SIZE:16, Rate:32, BurstSize:32, Experimenter:32>>;

encode_struct(#ofp_action_output{port = Port, max_len = MaxLen}) ->
    Type = ofp_v4_enum:to_int(action_type, output),
    Length = ?ACTION_OUTPUT_SIZE,
    PortInt = get_id(port_no, Port),
    MaxLenInt = get_id(max_len, MaxLen),
    <<Type:16, Length:16, PortInt:32, MaxLenInt:16, 0:48>>;
encode_struct(#ofp_action_group{group_id = Group}) ->
    Type = ofp_v4_enum:to_int(action_type, group),
    Length = ?ACTION_GROUP_SIZE,
    GroupInt = get_id(group, Group),
    <<Type:16, Length:16, GroupInt:32>>;
encode_struct(#ofp_action_set_queue{queue_id = Queue}) ->
    Type = ofp_v4_enum:to_int(action_type, set_queue),
    QueueInt = get_id(queue, Queue),
    Length = ?ACTION_SET_QUEUE_SIZE,
    <<Type:16, Length:16, QueueInt:32>>;
encode_struct(#ofp_action_set_mpls_ttl{mpls_ttl = TTL}) ->
    Type = ofp_v4_enum:to_int(action_type, set_mpls_ttl),
    Length = ?ACTION_SET_MPLS_TTL_SIZE,
    <<Type:16, Length:16, TTL:8, 0:24>>;
encode_struct(#ofp_action_dec_mpls_ttl{}) ->
    Type = ofp_v4_enum:to_int(action_type, dec_mpls_ttl),
    Length = ?ACTION_DEC_MPLS_TTL_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_set_nw_ttl{nw_ttl = TTL}) ->
    Type = ofp_v4_enum:to_int(action_type, set_nw_ttl),
    Length = ?ACTION_SET_NW_TTL_SIZE,
    <<Type:16, Length:16, TTL:8, 0:24>>;
encode_struct(#ofp_action_dec_nw_ttl{}) ->
    Type = ofp_v4_enum:to_int(action_type, dec_nw_ttl),
    Length = ?ACTION_DEC_NW_TTL_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_copy_ttl_out{}) ->
    Type = ofp_v4_enum:to_int(action_type, copy_ttl_out),
    Length = ?ACTION_COPY_TTL_OUT_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_copy_ttl_in{}) ->
    Type = ofp_v4_enum:to_int(action_type, copy_ttl_in),
    Length = ?ACTION_COPY_TTL_IN_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_push_vlan{ethertype = EtherType}) ->
    Type = ofp_v4_enum:to_int(action_type, push_vlan),
    Length = ?ACTION_PUSH_VLAN_SIZE,
    <<Type:16, Length:16, EtherType:16, 0:16>>;
encode_struct(#ofp_action_pop_vlan{}) ->
    Type = ofp_v4_enum:to_int(action_type, pop_vlan),
    Length = ?ACTION_POP_VLAN_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_push_mpls{ethertype = EtherType}) ->
    Type = ofp_v4_enum:to_int(action_type, push_mpls),
    Length = ?ACTION_PUSH_MPLS_SIZE,
    <<Type:16, Length:16, EtherType:16, 0:16>>;
encode_struct(#ofp_action_pop_mpls{ethertype = EtherType}) ->
    Type = ofp_v4_enum:to_int(action_type, pop_mpls),
    Length = ?ACTION_POP_MPLS_SIZE,
    <<Type:16, Length:16, EtherType:16, 0:16>>;
encode_struct(#ofp_action_push_pbb{ethertype = EtherType}) ->
    Type = ofp_v4_enum:to_int(action_type, push_pbb),
    Length = ?ACTION_PUSH_PBB_SIZE,
    <<Type:16, Length:16, EtherType:16, 0:16>>;
encode_struct(#ofp_action_pop_pbb{}) ->
    Type = ofp_v4_enum:to_int(action_type, pop_pbb),
    Length = ?ACTION_POP_PBB_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_set_field{field = Field}) ->
    Type = ofp_v4_enum:to_int(action_type, set_field),
    FieldBin = encode_struct(Field),
    FieldSize = size(FieldBin),
    PartialLength = ?ACTION_SET_FIELD_SIZE - 4 + FieldSize,
    Padding = ofp_utils:padding(PartialLength, 8),
    Length = PartialLength + Padding,
    <<Type:16, Length:16, FieldBin/bytes, 0:(Padding*8)>>;
encode_struct(#ofp_action_experimenter{
                 experimenter = ?INFOBLOX_EXPERIMENTER = Experimenter,
                 data = #ofp_action_set_field{} = Data}) ->
    Type = ofp_v4_enum:to_int(action_type, experimenter),
    DataBin = encode_struct(Data),
    Length = ?ACTION_EXPERIMENTER_SIZE + byte_size(DataBin),
    <<Type:16, Length:16, Experimenter:32, DataBin/bytes>>;
encode_struct(#ofp_action_experimenter{experimenter = Experimenter,
                                       data = Data}) ->
    Type = ofp_v4_enum:to_int(action_type, experimenter),
    Length = ?ACTION_EXPERIMENTER_SIZE + byte_size(Data),
    <<Type:16, Length:16, Experimenter:32, Data/bytes>>;
encode_struct(#ofp_instruction_goto_table{table_id = Table}) ->
    Type = ofp_v4_enum:to_int(instruction_type, goto_table),
    Length = ?INSTRUCTION_GOTO_TABLE_SIZE,
    <<Type:16, Length:16, Table:8, 0:24>>;
encode_struct(#ofp_instruction_write_metadata{metadata = Metadata,
                                              metadata_mask = MetaMask}) ->
    Type = ofp_v4_enum:to_int(instruction_type, write_metadata),
    Length = ?INSTRUCTION_WRITE_METADATA_SIZE,
    <<Type:16, Length:16, 0:32, Metadata:8/bytes, MetaMask:8/bytes>>;
encode_struct(#ofp_instruction_write_actions{actions = Actions}) ->
    Type = ofp_v4_enum:to_int(instruction_type, write_actions),
    ActionsBin = encode_list(Actions),
    Length = ?INSTRUCTION_WRITE_ACTIONS_SIZE + size(ActionsBin),
    <<Type:16, Length:16, 0:32, ActionsBin/bytes>>;
encode_struct(#ofp_instruction_apply_actions{actions = Actions}) ->
    Type = ofp_v4_enum:to_int(instruction_type, apply_actions),
    ActionsBin = encode_list(Actions),
    Length = ?INSTRUCTION_APPLY_ACTIONS_SIZE + size(ActionsBin),
    <<Type:16, Length:16, 0:32, ActionsBin/bytes>>;
encode_struct(#ofp_instruction_clear_actions{}) ->
    Type = ofp_v4_enum:to_int(instruction_type, clear_actions),
    Length = ?INSTRUCTION_CLEAR_ACTIONS_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_instruction_meter{meter_id = MeterId}) ->
    Type = ofp_v4_enum:to_int(instruction_type, meter),
    MeterIdInt = get_id(meter_id, MeterId),
    Length = ?INSTRUCTION_METER_SIZE,
    <<Type:16, Length:16, MeterIdInt:32>>;
encode_struct(#ofp_instruction_experimenter{experimenter = Experimenter,
                                            data = Data}) ->
    Type = ofp_v4_enum:to_int(instruction_type, experimenter),
    Length = ?INSTRUCTION_EXPERIMENTER_SIZE + byte_size(Data),
    <<Type:16, Length:16, Experimenter:32, Data/bytes>>;
encode_struct(#ofp_bucket{weight = Weight, watch_port = Port,
                          watch_group = Group, actions = Actions}) ->
    ActionsBin = encode_list(Actions),
    Length = ?BUCKET_SIZE + size(ActionsBin),
    <<Length:16, Weight:16, Port:32, Group:32, 0:32, ActionsBin/bytes>>;
encode_struct(#ofp_flow_stats{table_id = Table, duration_sec = Sec,
                              duration_nsec = NSec, priority = Priority,
                              idle_timeout = Idle, hard_timeout = Hard,
                              flags = Flags, cookie = Cookie,
                              packet_count = PCount, byte_count = BCount,
                              match = Match, instructions = Instructions}) ->
    MatchBin = encode_struct(Match),
    InstrsBin = encode_list(Instructions),
    FlagsBin = flags_to_binary(flow_mod_flags, Flags, 2),
    Length = ?FLOW_STATS_SIZE + size(MatchBin) - ?MATCH_SIZE + size(InstrsBin),
    <<Length:16, Table:8, 0:8, Sec:32, NSec:32, Priority:16, Idle:16, Hard:16,
      FlagsBin:2/bytes, 0:32, Cookie:8/bytes, PCount:64, BCount:64, MatchBin/bytes,
      InstrsBin/bytes>>;
encode_struct(#ofp_table_stats{table_id = Table, active_count = ACount,
                               lookup_count = LCount,
                               matched_count = MCount}) ->
    <<Table:8, 0:24, ACount:32, LCount:64, MCount:64>>;
encode_struct(#ofp_port_stats{port_no = Port,
                              rx_packets = RXPackets, tx_packets = TXPackets,
                              rx_bytes = RXBytes, tx_bytes = TXBytes,
                              rx_dropped = RXDropped, tx_dropped = TXDropped,
                              rx_errors = RXErrors, tx_errors = TXErrors,
                              rx_frame_err = FrameErr, rx_over_err = OverErr,
                              rx_crc_err = CRCErr, collisions = Collisions,
                              duration_sec = DSec, duration_nsec = DNSec}) ->
    PortInt = get_id(port_no, Port),
    <<PortInt:32, 0:32, RXPackets:64,
      TXPackets:64, RXBytes:64, TXBytes:64, RXDropped:64, TXDropped:64,
      RXErrors:64, TXErrors:64, FrameErr:64, OverErr:64, CRCErr:64,
      Collisions:64, DSec:32, DNSec:32>>;
encode_struct(#ofp_queue_stats{port_no = Port, queue_id = Queue,
                               tx_bytes = Bytes, tx_packets = Packets,
                               tx_errors = Errors, duration_sec = DSec,
                               duration_nsec = DNSec}) ->
    <<Port:32, Queue:32, Bytes:64, Packets:64, Errors:64, DSec:32, DNSec:32>>;
encode_struct(#ofp_group_stats{group_id = Group, ref_count = RefCount,
                               packet_count = PCount, byte_count = BCount,
                               duration_sec = DSec, duration_nsec = DNSec,
                               bucket_stats = Buckets}) ->
    GroupInt = get_id(group, Group),
    BucketsBin = encode_list(Buckets),
    Length = ?GROUP_STATS_SIZE + size(BucketsBin),
    <<Length:16, 0:16, GroupInt:32,
      RefCount:32, 0:32, PCount:64,
      BCount:64, DSec:32, DNSec:32, BucketsBin/bytes>>;
encode_struct(#ofp_bucket_counter{packet_count = PCount,
                                  byte_count = BCount}) ->
    <<PCount:64, BCount:64>>;
encode_struct(#ofp_group_desc_stats{type = Type, group_id = Group,
                                    buckets = Buckets}) ->
    TypeInt = ofp_v4_enum:to_int(group_type, Type),
    GroupInt = get_id(group, Group),
    BucketsBin = encode_list(Buckets),
    Length = ?GROUP_DESC_STATS_SIZE + size(BucketsBin),
    <<Length:16, TypeInt:8, 0:8, GroupInt:32, BucketsBin/bytes>>;
encode_struct(#ofp_meter_stats{meter_id = MeterId, flow_count = FlowCount,
                               packet_in_count = PacketInCount,
                               byte_in_count = ByteInCount,
                               duration_sec = DSec, duration_nsec = DNSec,
                               band_stats = BandStats}) ->
    BandStatsBin = encode_list(BandStats),
    Length = ?METER_STATS_SIZE + byte_size(BandStatsBin),
    <<MeterId:32, Length:16, 0:48, FlowCount:32, PacketInCount:64,
      ByteInCount:64, DSec:32, DNSec:32, BandStatsBin/bytes>>;
encode_struct(#ofp_meter_band_stats{packet_band_count = PBC,
                                    byte_band_count = BBC}) ->
    <<PBC:64, BBC:64>>;
encode_struct(#ofp_meter_config{flags = Flags, meter_id = _MeterId,
                                bands = Bands}) ->
    MeterIdInt = get_id(meter_id, meterid),
    FlagsBin = flags_to_binary(meter_flag, Flags, 2),
    BandsBin = encode_list(Bands),
    Length = ?METER_CONFIG_SIZE + byte_size(BandsBin),
    <<Length:16, FlagsBin:16/bits, MeterIdInt:32, BandsBin/bytes>>;
encode_struct(#ofp_oxm_experimenter{ body = Body,
                                     experimenter = Experimenter }) ->
    OfpFieldBin = encode_struct(Body),
    <<0:24, Experimenter:16, OfpFieldBin/bytes>>;

encode_struct(#ofp_action_experimenter_header{ type = Type,
                                               experimenter = Experimenter }) ->
    TypeInt = ofp_v4_enum:to_int(action_type, Type),
    <<TypeInt:16,?ACTION_EXPERIMENTER_SIZE:16,Experimenter:32>>.

encode_async_masks({PacketInMask1, PacketInMask2},
                   {PortStatusMask1, PortStatusMask2},
                   {FlowRemovedMask1, FlowRemovedMask2}) ->
    PIn1 = flags_to_binary(packet_in_reason, PacketInMask1, 4),
    PIn2 = flags_to_binary(packet_in_reason, PacketInMask2, 4),
    PS1 = flags_to_binary(port_reason, PortStatusMask1, 4),
    PS2 = flags_to_binary(port_reason, PortStatusMask2, 4),
    FR1 = flags_to_binary(flow_removed_reason, FlowRemovedMask1, 4),
    FR2 = flags_to_binary(flow_removed_reason, FlowRemovedMask2, 4),
    <<PIn1:32/bits, PIn2:32/bits, PS1:32/bits, PS2:32/bits,
      FR1:32/bits, FR2:32/bits>>.

encode_bitmap([], Size, Acc) ->
    Bytes = (Size + 1) * 32,
    <<Acc:Bytes>>;
encode_bitmap([H|Rest], Size, Acc) ->
    Index = (Size - H div 32) * 32 + H rem 32,
    encode_bitmap(Rest, Size, Acc bor (1 bsl Index)).

encode_bitmap(List) ->
    Size = lists:max(List) div 32,
    encode_bitmap(List, Size, 0).

encode_hello_element({versionbitmap, Versions}) ->
    BitmapBin = encode_bitmap(Versions),
    TypeInt = ofp_v4_enum:to_int(hello_elem, versionbitmap),
    SizeInt = 4 + size(BitmapBin),
    <<TypeInt:16, SizeInt:16, BitmapBin/bytes>>;
encode_hello_element(_) ->
    <<>>.

encode_hello_elements([], Acc) ->
    list_to_binary(Acc);
encode_hello_elements([H|Rest], Acc) ->
    encode_hello_elements(Rest, [encode_hello_element(H)|Acc]).

%%% Messages -------------------------------------------------------------------

encode_body(#ofp_hello{elements = Elements}) ->
    encode_hello_elements(Elements, []);
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

encode_body(#ofp_experimenter{experimenter = ?INFOBLOX_EXPERIMENTER,
                              exp_type = Type,
                              data = Data}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type,Type),
    DataBin = encode_body(Data),
    <<?INFOBLOX_EXPERIMENTER:32, TypeInt:32, DataBin/bytes>>;

encode_body(#ofp_experimenter{experimenter = Experimenter,
                              exp_type = Type,
                              data = Data}) ->
    <<Experimenter:32, Type:32, Data/bytes>>;
encode_body(#ofp_features_request{}) ->
    <<>>;
encode_body(#ofp_features_reply{datapath_mac = DataPathMac,
                                datapath_id = DataPathID, n_buffers = NBuffers,
                                n_tables = NTables, auxiliary_id = AuxId,
                                capabilities = Capabilities}) ->
    CapaBin = flags_to_binary(capabilities, Capabilities, 4),
    <<DataPathID:16, DataPathMac:48/bits, NBuffers:32,
      NTables:8, AuxId:8, 0:16, CapaBin:32/bits, 0:32>>;
encode_body(#ofp_get_config_request{}) ->
    <<>>;
encode_body(#ofp_get_config_reply{flags = Flags, miss_send_len = Miss}) ->
    FlagsBin = flags_to_binary(config_flags, Flags, 2),
    MissInt = get_id(miss_send_len, Miss),
    <<FlagsBin:16/bits, MissInt:16>>;
encode_body(#ofp_set_config{flags = Flags, miss_send_len = Miss}) ->
    FlagsBin = flags_to_binary(config_flags, Flags, 2),
    MissInt = get_id(miss_send_len, Miss),
    <<FlagsBin:16/bits, MissInt:16>>;
encode_body(#ofp_packet_in{buffer_id = BufferId, reason = Reason,
                           table_id = TableId, cookie = Cookie,
                           match = Match, data = Data}) ->
    BufferIdInt = get_id(buffer_id, BufferId),
    ReasonInt = ofp_v4_enum:to_int(packet_in_reason, Reason),
    MatchBin = encode_struct(Match),
    TotalLen = byte_size(Data),
    <<BufferIdInt:32, TotalLen:16, ReasonInt:8, TableId:8, Cookie:64/bits,
      MatchBin/bytes, 0:16, Data/bytes>>;
encode_body(#ofp_flow_removed{cookie = Cookie, priority = Priority,
                              reason = Reason, table_id = TableId,
                              duration_sec = Sec, duration_nsec = NSec,
                              idle_timeout = Idle, hard_timeout = Hard,
                              packet_count = PCount, byte_count = BCount,
                              match = Match}) ->
    ReasonInt = ofp_v4_enum:to_int(flow_removed_reason, Reason),
    MatchBin = encode_struct(Match),
    <<Cookie:8/bytes, Priority:16, ReasonInt:8, TableId:8, Sec:32, NSec:32,
      Idle:16, Hard:16, PCount:64, BCount:64, MatchBin/bytes>>;
encode_body(#ofp_port_status{reason = Reason, desc = Port}) ->
    ReasonInt = ofp_v4_enum:to_int(port_reason, Reason),
    PortBin = encode_struct(Port),
    <<ReasonInt:8, 0:56, PortBin/bytes>>;
encode_body(#ofp_packet_out{buffer_id = BufferId, in_port = Port,
                            actions = Actions, data = Data}) ->
    BufferIdInt = get_id(buffer_id, BufferId),
    PortInt = get_id(port_no, Port),
    ActionsBin = encode_list(Actions),
    ActionsLength = size(ActionsBin),
    <<BufferIdInt:32, PortInt:32,
      ActionsLength:16, 0:48, ActionsBin/bytes, Data/bytes>>;
encode_body(#ofp_flow_mod{cookie = Cookie, cookie_mask = CookieMask,
                          table_id = Table, command = Command,
                          idle_timeout = Idle, hard_timeout = Hard,
                          priority = Priority, buffer_id = BufferId,
                          out_port = OutPort, out_group = OutGroup,
                          flags = Flags, match = Match,
                          instructions = Instructions}) ->
    TableInt = get_id(table, Table),
    BufferIdInt = get_id(buffer_id, BufferId),
    CommandInt = ofp_v4_enum:to_int(flow_mod_command, Command),
    OutPortInt = get_id(port_no, OutPort),
    OutGroupInt = get_id(group, OutGroup),
    FlagsBin = flags_to_binary(flow_mod_flags, Flags, 2),
    MatchBin = encode_struct(Match),
    InstructionsBin = encode_list(Instructions),
    <<Cookie:8/bytes, CookieMask:8/bytes, TableInt:8, CommandInt:8,
      Idle:16, Hard:16, Priority:16, BufferIdInt:32, OutPortInt:32,
      OutGroupInt:32, FlagsBin:2/bytes, 0:16, MatchBin/bytes,
      InstructionsBin/bytes>>;
encode_body(#ofp_group_mod{command = Command, type = Type,
                           group_id = Group, buckets = Buckets}) ->
    CommandInt = ofp_v4_enum:to_int(group_mod_command, Command),
    TypeInt = ofp_v4_enum:to_int(group_type, Type),
    GroupInt = get_id(group, Group),
    BucketsBin = encode_list(Buckets),
    <<CommandInt:16, TypeInt:8, 0:8, GroupInt:32, BucketsBin/bytes>>;
encode_body(#ofp_port_mod{port_no = Port, hw_addr = Addr,
                          config = Config, mask = Mask,
                          advertise = Advertise}) ->
    PortInt = get_id(port_no, Port),
    ConfigBin = flags_to_binary(port_config, Config, 4),
    MaskBin = flags_to_binary(port_config, Mask, 4),
    AdvertiseBin = flags_to_binary(port_features, Advertise, 4),
    <<PortInt:32, 0:32, Addr:6/bytes, 0:16, ConfigBin:4/bytes,
      MaskBin:4/bytes, AdvertiseBin:4/bytes, 0:32>>;
encode_body(#ofp_table_mod{table_id = Table}) ->
    TableInt = get_id(table, Table),
    <<TableInt:8, 0:24, 0:32>>;
%% Multipart Messages ----------------------------------------------------------
encode_body(#ofp_desc_request{flags = Flags}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, desc),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32>>;
encode_body(#ofp_desc_reply{flags = Flags, mfr_desc = MFR,
                            hw_desc = HW, sw_desc = SW,
                            serial_num = Serial, dp_desc = DP}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, desc),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    MFRPad = (?DESC_STR_LEN - size(MFR)) * 8,
    HWPad = (?DESC_STR_LEN - size(HW)) * 8,
    SWPad = (?DESC_STR_LEN - size(SW)) * 8,
    SerialPad = (?SERIAL_NUM_LEN - size(Serial)) * 8,
    DPPad = (?DESC_STR_LEN - size(DP)) * 8,
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      MFR/bytes, 0:MFRPad, HW/bytes, 0:HWPad,
      SW/bytes, 0:SWPad, Serial/bytes, 0:SerialPad,
      DP/bytes, 0:DPPad>>;
encode_body(#ofp_flow_stats_request{flags = Flags, table_id = Table,
                                    out_port = Port, out_group = Group,
                                    cookie = Cookie, cookie_mask = CookieMask,
                                    match = Match}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, flow_stats),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    TableInt = get_id(table, Table),
    PortInt = get_id(port_no, Port),
    GroupInt = get_id(group, Group),
    MatchBin = encode_struct(Match),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      TableInt:8, 0:24, PortInt:32,
      GroupInt:32, 0:32, Cookie:8/bytes, CookieMask:8/bytes,
      MatchBin/bytes>>;
encode_body(#ofp_flow_stats_reply{flags = Flags, body = Stats}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, flow_stats),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32, StatsBin/bytes>>;
encode_body(#ofp_aggregate_stats_request{flags = Flags,
                                         table_id = Table, out_port = Port,
                                         out_group = Group, cookie = Cookie,
                                         cookie_mask = CookieMask,
                                         match = Match}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, aggregate_stats),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    TableInt = get_id(table, Table),
    PortInt = get_id(port_no, Port),
    GroupInt = get_id(group, Group),
    MatchBin = encode_struct(Match),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      TableInt:8, 0:24, PortInt:32,
      GroupInt:32, 0:32, Cookie:8/bytes, CookieMask:8/bytes,
      MatchBin/bytes>>;
encode_body(#ofp_aggregate_stats_reply{flags = Flags,
                                       packet_count = PCount,
                                       byte_count = BCount,
                                       flow_count = FCount}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, aggregate_stats),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      PCount:64, BCount:64, FCount:32, 0:32>>;
encode_body(#ofp_table_stats_request{flags = Flags}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, table_stats),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32>>;
encode_body(#ofp_table_stats_reply{flags = Flags, body = Stats}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, table_stats),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_table_features_request{} = Request) ->
    table_features_request(Request);
encode_body(#ofp_table_features_reply{} = Reply) ->
    table_features_reply(Reply);
encode_body(#ofp_port_stats_request{flags = Flags, port_no = Port}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, port_stats),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    PortInt = get_id(port_no, Port),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      PortInt:32, 0:32>>;
encode_body(#ofp_port_stats_reply{flags = Flags, body = Stats}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, port_stats),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_port_desc_request{flags = Flags}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, port_desc),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin/bytes, 0:32>>;
encode_body(#ofp_port_desc_reply{flags = Flags, body = Ports}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, port_desc),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    PortsBin = encode_list(Ports),
    <<TypeInt:16, FlagsBin/bytes, 0:32, PortsBin/bytes>>;
encode_body(#ofp_port_desc_reply_v6{flags = Flags, body = Ports}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, port_desc_v6),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    PortsBin = encode_list(Ports),
    <<TypeInt:16, FlagsBin/bytes, 0:32, PortsBin/bytes>>;
encode_body(#ofp_queue_stats_request{flags = Flags,
                                     port_no = Port, queue_id = Queue}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, queue_stats),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    PortInt = get_id(port_no, Port),
    QueueInt = get_id(queue, Queue),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      PortInt:32, QueueInt:32>>;
encode_body(#ofp_queue_stats_reply{flags = Flags, body = Stats}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, queue_stats),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_group_stats_request{flags = Flags,
                                     group_id = Group}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, group_stats),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    GroupInt = get_id(group, Group),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      GroupInt:32, 0:32>>;
encode_body(#ofp_group_stats_reply{flags = Flags, body = Stats}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, group_stats),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_group_desc_request{flags = Flags}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, group_desc),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32>>;
encode_body(#ofp_group_desc_reply{flags = Flags, body = Stats}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, group_desc),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_group_features_request{flags = Flags}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, group_features),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32>>;
encode_body(#ofp_group_features_reply{flags = Flags, types = Types,
                                      capabilities = Capabilities,
                                      max_groups = {Max1, Max2, Max3, Max4},
                                      actions = {Actions1, Actions2,
                                                 Actions3, Actions4}}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, group_features),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    TypesBin = flags_to_binary(group_type, Types, 4),
    CapabilitiesBin = flags_to_binary(group_capabilities, Capabilities, 4),
    Actions1Bin = flags_to_binary(action_type, Actions1, 4),
    Actions2Bin = flags_to_binary(action_type, Actions2, 4),
    Actions3Bin = flags_to_binary(action_type, Actions3, 4),
    Actions4Bin = flags_to_binary(action_type, Actions4, 4),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      TypesBin/bytes, CapabilitiesBin/bytes,
      Max1:32, Max2:32, Max3:32, Max4:32,
      Actions1Bin/bytes, Actions2Bin/bytes, Actions3Bin/bytes,
      Actions4Bin/bytes>>;

encode_body(#ofp_meter_stats_request{flags = Flags, meter_id = MeterId}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, meter_stats),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    MeterIdInt = get_id(meter_id, MeterId),
    <<TypeInt:16, FlagsBin/bytes, 0:32, MeterIdInt:32, 0:32>>;
encode_body(#ofp_meter_stats_reply{flags = Flags, body = MeterStats}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, meter_stats),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    StatsBin = encode_list(MeterStats),
    <<TypeInt:16, FlagsBin/bytes, 0:32, StatsBin/bytes>>;
encode_body(#ofp_meter_config_request{flags = Flags, meter_id = MeterId}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, meter_config),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    MeterIdInt = get_id(meter_id, MeterId),
    <<TypeInt:16, FlagsBin/bytes, 0:32, MeterIdInt:32, 0:32>>;
encode_body(#ofp_meter_config_reply{flags = Flags, body = MeterConfigs}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, meter_config),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    MeterConfigsBin = encode_list(MeterConfigs),
    <<TypeInt:16, FlagsBin/bytes, 0:32, MeterConfigsBin/bytes>>;
encode_body(#ofp_meter_features_request{flags = Flags}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, meter_features),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin/bytes, 0:32>>;
encode_body(#ofp_meter_features_reply{flags = Flags, max_meter = MaxMeter,
                                      band_types = BandTypes,
                                      capabilities = Capabilities,
                                      max_bands = MaxBands,
                                      max_color = MaxColor}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, meter_features),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    BandTypesBin = flags_to_binary(meter_band_type, BandTypes, 4),
    CapabilitiesBin = flags_to_binary(meter_flag, Capabilities, 4),
    <<TypeInt:16, FlagsBin/bytes, 0:32, MaxMeter:32, BandTypesBin:32/bits,
      CapabilitiesBin:32/bits, MaxBands:8, MaxColor:8, 0:16>>;

encode_body(#ofp_experimenter_request{flags = Flags,
                                      experimenter = ?INFOBLOX_EXPERIMENTER,
                                      exp_type = ExpType, data = Data}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, experimenter),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    ExpTypeInt = ofp_v4_enum:to_int(multipart_type,ExpType),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      ?INFOBLOX_EXPERIMENTER:32, ExpTypeInt:32, Data/bytes>>;

encode_body(#ofp_experimenter_request{flags = Flags,
                                      experimenter = Experimenter,
                                      exp_type = ExpType, data = Data}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, experimenter),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      Experimenter:32, ExpType:32, Data/bytes>>;
encode_body(#ofp_experimenter_reply{flags = Flags,
                                    experimenter = ?INFOBLOX_EXPERIMENTER,
                                    exp_type = ExpType, data = UnEncData}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, experimenter),
    ExpTypeInt = ofp_v4_enum:to_int(multipart_type, ExpType),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    Data = encode_body(UnEncData),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      ?INFOBLOX_EXPERIMENTER:32, ExpTypeInt:32, Data/bytes>>;
encode_body(#ofp_experimenter_reply{flags = Flags,
                                    experimenter = Experimenter,
                                    exp_type = ExpType, data = Data}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, experimenter),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      Experimenter:32, ExpType:32, Data/bytes>>;
%% -----------------------------------------------------------------------------
encode_body(#ofp_barrier_request{}) ->
    <<>>;
encode_body(#ofp_barrier_reply{}) ->
    <<>>;
encode_body(#ofp_queue_get_config_request{port = Port}) ->
    PortInt = get_id(port_no, Port),
    <<PortInt:32, 0:32>>;
encode_body(#ofp_queue_get_config_reply{port = Port, queues = Queues}) ->
    PortInt = get_id(port_no, Port),
    QueuesBin = encode_list(Queues),
    <<PortInt:32, 0:32, QueuesBin/bytes>>;
encode_body(#ofp_role_request{role = Role, generation_id = Gen}) ->
    RoleInt = ofp_v4_enum:to_int(controller_role, Role),
    <<RoleInt:32, 0:32, Gen:64>>;
encode_body(#ofp_role_reply{role = Role, generation_id = Gen}) ->
    RoleInt = ofp_v4_enum:to_int(controller_role, Role),
    <<RoleInt:32, 0:32, Gen:64>>;
encode_body(#ofp_get_async_request{}) ->
    <<>>;
encode_body(#ofp_get_async_reply{packet_in_mask = PacketInMask,
                                 port_status_mask = PortStatusMask,
                                 flow_removed_mask = FlowRemovedMask}) ->
    encode_async_masks(PacketInMask, PortStatusMask, FlowRemovedMask);
encode_body(#ofp_set_async{packet_in_mask = PacketInMask,
                           port_status_mask = PortStatusMask,
                           flow_removed_mask = FlowRemovedMask}) ->
    encode_async_masks(PacketInMask, PortStatusMask, FlowRemovedMask);
encode_body(#ofp_meter_mod{command = Command,
                           flags = Flags,
                           meter_id = MeterId,
                           bands = Bands}) ->
    CommandInt = get_id(meter_mod_command, Command),
    FlagsBin = flags_to_binary(meter_flag, Flags, 2),
    MeterIdInt = get_id(meter_id, MeterId),
    BandsBin = encode_list(Bands),
    <<CommandInt:16, FlagsBin:2/bytes, MeterIdInt:32, BandsBin/bytes>>;
encode_body(#ofp_multipart_request{ %%header = Header,
                                    type = Type,
                                    flags = Flags,
                                    body = Body }) ->
    %%BinHeader = encode_struct(Header),
    TypeInt = ofp_v4_enum:to_int(multipart_type, Type),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    %%, i get a entirly diff message, when i add header
    %% <<BinHeader/bytes, TypeInt:16, FlagsBin:2/bytes, 0:40, Body/bytes>>;
    EncBody = encode_body(Body),
    <<TypeInt:16, FlagsBin:2/bytes, 0:40, EncBody/bytes>>; 

encode_body(Other) ->
    throw({bad_message, Other}).

%% A.3.5.5 Table Features ------------------------------------------------------

table_features_request(#ofp_table_features_request{flags = Flags,
                                                   body = Features}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, table_features),
    FlagsBin = flags_to_binary(multipart_request_flags, Flags, 2),
    BodyBin = list_to_binary([table_features(Feature) || Feature <- Features]),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32, BodyBin/bytes>>.

table_features_reply(#ofp_table_features_reply{flags = Flags,
                                               body = Features}) ->
    TypeInt = ofp_v4_enum:to_int(multipart_type, table_features),
    FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    BodyBin = list_to_binary([table_features(Feature) || Feature <- Features]),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32, BodyBin/bytes>>.

table_features(#ofp_table_features{table_id = TableId,
                                   name = Name,
                                   metadata_match = MetadataMatch,
                                   metadata_write = MetadataWrite,
                                   max_entries = MaxEntries,
                                   properties = Properties}) ->
    TableIdInt = get_id(table, TableId),
    NamePadding = (?OFP_MAX_TABLE_NAME_LEN - byte_size(Name)) * 8,
    PropertiesBin = list_to_binary([table_feature_prop(Property)
                                    || Property <- Properties]),
    Length = 64 + byte_size(PropertiesBin),
    <<Length:16, TableIdInt:8, 0:40, Name/bytes, 0:NamePadding,
      MetadataMatch:8/bytes, MetadataWrite:8/bytes, 0:32, MaxEntries:32,
      PropertiesBin/bytes>>.

table_feature_prop(#ofp_table_feature_prop_instructions{} = Prop) ->
    table_feature_prop_instructions(Prop);
table_feature_prop(#ofp_table_feature_prop_instructions_miss{} = Prop) ->
    table_feature_prop_instructions_miss(Prop);
table_feature_prop(#ofp_table_feature_prop_next_tables{} = Prop) ->
    table_feature_prop_next_tables(Prop);
table_feature_prop(#ofp_table_feature_prop_next_tables_miss{} = Prop) ->
    table_feature_prop_next_tables_miss(Prop);
table_feature_prop(#ofp_table_feature_prop_write_actions{} = Prop) ->
    table_feature_prop_write_actions(Prop);
table_feature_prop(#ofp_table_feature_prop_write_actions_miss{} = Prop) ->
    table_feature_prop_write_actions_miss(Prop);
table_feature_prop(#ofp_table_feature_prop_apply_actions{} = Prop) ->
    table_feature_prop_apply_actions(Prop);
table_feature_prop(#ofp_table_feature_prop_apply_actions_miss{} = Prop) ->
    table_feature_prop_apply_actions_miss(Prop);
table_feature_prop(#ofp_table_feature_prop_match{} = Prop) ->
    table_feature_prop_match(Prop);
table_feature_prop(#ofp_table_feature_prop_wildcards{} = Prop) ->
    table_feature_prop_wildcards(Prop);
table_feature_prop(#ofp_table_feature_prop_write_setfield{} = Prop) ->
    table_feature_prop_write_setfield(Prop);
table_feature_prop(#ofp_table_feature_prop_write_setfield_miss{} = Prop) ->
    table_feature_prop_write_setfield_miss(Prop);
table_feature_prop(#ofp_table_feature_prop_apply_setfield{} = Prop) ->
    table_feature_prop_apply_setfield(Prop);
table_feature_prop(#ofp_table_feature_prop_apply_setfield_miss{} = Prop) ->
    table_feature_prop_apply_setfield_miss(Prop);
table_feature_prop(#ofp_table_feature_prop_experimenter{} = Prop) ->
    table_feature_prop_experimenter(Prop);
table_feature_prop(#ofp_table_feature_prop_experimenter_miss{} = Prop) ->
    table_feature_prop_experimenter_miss(Prop).

table_feature_prop_instructions(#ofp_table_feature_prop_instructions{
                                   instruction_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, instructions),
    IdsBin = list_to_binary([table_feature_prop_instruction_id(Id)
                             || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_instructions_miss(#ofp_table_feature_prop_instructions_miss{
                                        instruction_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, instructions_miss),
    IdsBin = list_to_binary([table_feature_prop_instruction_id(Id)
                             || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_next_tables(#ofp_table_feature_prop_next_tables{
                                  next_table_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, next_tables),
    IdsBin = list_to_binary([<<Id:8>> || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_next_tables_miss(#ofp_table_feature_prop_next_tables_miss{
                                       next_table_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, next_tables_miss),
    IdsBin = list_to_binary([<<Id:8>> || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_write_actions(#ofp_table_feature_prop_write_actions{
                                    action_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, write_actions),
    IdsBin = list_to_binary([table_feature_prop_action_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_write_actions_miss(
  #ofp_table_feature_prop_write_actions_miss{action_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, write_actions_miss),
    IdsBin = list_to_binary([table_feature_prop_action_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_apply_actions(#ofp_table_feature_prop_apply_actions{
                                    action_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, apply_actions),
    IdsBin = list_to_binary([table_feature_prop_action_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_apply_actions_miss(
  #ofp_table_feature_prop_apply_actions_miss{action_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, apply_actions_miss),
    IdsBin = list_to_binary([table_feature_prop_action_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_match(#ofp_table_feature_prop_match{
                            oxm_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, match),
    IdsBin = list_to_binary([table_feature_prop_field_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_wildcards(#ofp_table_feature_prop_wildcards{
                                oxm_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, wildcards),
    IdsBin = list_to_binary([table_feature_prop_field_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_write_setfield(#ofp_table_feature_prop_write_setfield{
                                     oxm_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, write_setfield),
    IdsBin = list_to_binary([table_feature_prop_field_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_write_setfield_miss(
  #ofp_table_feature_prop_write_setfield_miss{oxm_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, write_setfield_miss),
    IdsBin = list_to_binary([table_feature_prop_field_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_apply_setfield(#ofp_table_feature_prop_apply_setfield{
                                     oxm_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, apply_setfield),
    IdsBin = list_to_binary([table_feature_prop_field_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_apply_setfield_miss(
  #ofp_table_feature_prop_apply_setfield_miss{oxm_ids = Ids}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, apply_setfield_miss),
    IdsBin = list_to_binary([table_feature_prop_field_id(Id) || Id <- Ids]),
    Length = 4 + byte_size(IdsBin),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, IdsBin/bytes, 0:Padding>>.

table_feature_prop_experimenter(#ofp_table_feature_prop_experimenter{
                                   experimenter = Experimenter,
                                   exp_type = ExpType,
                                   data = Data}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, experimenter),
    Length = 12 + byte_size(Data),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, Experimenter:32, ExpType:32, Data/bytes,
      0:Padding>>.

table_feature_prop_experimenter_miss(#ofp_table_feature_prop_experimenter_miss{
                                        experimenter = Experimenter,
                                        exp_type = ExpType,
                                        data = Data}) ->
    TypeInt = ofp_v4_enum:to_int(table_feature_prop_type, experimenter_miss),
    Length = 12 + byte_size(Data),
    Padding = ofp_utils:padding(Length, 8) * 8,
    <<TypeInt:16, Length:16, Experimenter:32, ExpType:32, Data/bytes,
      0:Padding>>.

table_feature_prop_instruction_id({experimenter, Id}) when is_integer(Id) ->
    ExperimenterInt = ofp_v4_enum:to_int(instruction_type, experimenter),
    <<ExperimenterInt:16, 8:16, Id:32>>;
table_feature_prop_instruction_id(Id) when is_atom(Id) ->
    IdInt = ofp_v4_enum:to_int(instruction_type, Id),
    <<IdInt:16, 4:16>>.

table_feature_prop_action_id({experimenter, Id}) when is_integer(Id) ->
    ExperimenterInt = ofp_v4_enum:to_int(action_type, experimenter),
    <<ExperimenterInt:16, 8:16, Id:32>>;
table_feature_prop_action_id(Id) when is_atom(Id) ->
    IdInt = ofp_v4_enum:to_int(action_type, Id),
    <<IdInt:16, 4:16>>.

table_feature_prop_field_id({experimenter, Id}) when is_integer(Id) ->
    ExperimenterInt = ofp_v4_enum:to_int(oxm_class, experimenter),
    <<ExperimenterInt:16, 0:7, 0:1, 4:8, Id:32>>;
table_feature_prop_field_id(Id) when is_atom(Id) ->
    ClassInt = ofp_v4_enum:to_int(oxm_class, openflow_basic),
    IdInt = ofp_v4_enum:to_int(oxm_ofb_match_fields, Id),
    <<ClassInt:16, IdInt:7, 0:1, 0:8>>.

%%------------------------------------------------------------------------------
%% Helper functions
%%------------------------------------------------------------------------------

flags_to_binary(Type, Flags, Size) ->
    ofp_utils:flags_to_binary(ofp_v4_enum, Type, Flags, Size).

get_id(Enum, Value) ->
    ofp_utils:get_enum_value(ofp_v4_enum, Enum, Value).

-spec encode_list(list()) -> binary().
encode_list(List) ->
    ofp_utils:encode_list(fun encode_struct/1, List, <<>>).

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
    ofp_v4_enum:to_int(type, experimenter);
type_int(#ofp_features_request{}) ->
    ofp_v4_enum:to_int(type, features_request);
type_int(#ofp_features_reply{}) ->
    ofp_v4_enum:to_int(type, features_reply);
type_int(#ofp_get_config_request{}) ->
    ofp_v4_enum:to_int(type, get_config_request);
type_int(#ofp_get_config_reply{}) ->
    ofp_v4_enum:to_int(type, get_config_reply);
type_int(#ofp_set_config{}) ->
    ofp_v4_enum:to_int(type, set_config);
type_int(#ofp_packet_in{}) ->
    ofp_v4_enum:to_int(type, packet_in);
type_int(#ofp_flow_removed{}) ->
    ofp_v4_enum:to_int(type, flow_removed);
type_int(#ofp_port_status{}) ->
    ofp_v4_enum:to_int(type, port_status);
type_int(#ofp_packet_out{}) ->
    ofp_v4_enum:to_int(type, packet_out);
type_int(#ofp_flow_mod{}) ->
    ofp_v4_enum:to_int(type, flow_mod);
type_int(#ofp_group_mod{}) ->
    ofp_v4_enum:to_int(type, group_mod);
type_int(#ofp_port_mod{}) ->
    ofp_v4_enum:to_int(type, port_mod);
type_int(#ofp_table_mod{}) ->
    ofp_v4_enum:to_int(type, table_mod);
type_int(#ofp_desc_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_desc_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_flow_stats_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_flow_stats_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_aggregate_stats_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_aggregate_stats_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_table_stats_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_table_stats_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_table_features_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_table_features_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_port_stats_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_port_stats_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_port_desc_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_port_desc_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_queue_stats_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_queue_stats_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_group_stats_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_group_stats_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_group_desc_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_group_desc_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_group_features_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_group_features_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_meter_stats_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_meter_stats_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_meter_config_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_meter_config_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_meter_features_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_meter_features_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_experimenter_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request);
type_int(#ofp_experimenter_reply{}) ->
    ofp_v4_enum:to_int(type, multipart_reply);
type_int(#ofp_barrier_request{}) ->
    ofp_v4_enum:to_int(type, barrier_request);
type_int(#ofp_barrier_reply{}) ->
    ofp_v4_enum:to_int(type, barrier_reply);
type_int(#ofp_queue_get_config_request{}) ->
    ofp_v4_enum:to_int(type, queue_get_config_request);
type_int(#ofp_queue_get_config_reply{}) ->
    ofp_v4_enum:to_int(type, queue_get_config_reply);
type_int(#ofp_role_request{}) ->
    ofp_v4_enum:to_int(type, role_request);
type_int(#ofp_role_reply{}) ->
    ofp_v4_enum:to_int(type, role_reply);
type_int(#ofp_get_async_request{}) ->
    ofp_v4_enum:to_int(type, get_async_request);
type_int(#ofp_get_async_reply{}) ->
    ofp_v4_enum:to_int(type, get_async_reply);
type_int(#ofp_set_async{}) ->   
    ofp_v4_enum:to_int(type, set_async);
type_int(#ofp_meter_mod{}) ->
    ofp_v4_enum:to_int(type, meter_mod);
type_int(#ofp_multipart_request{}) ->
    ofp_v4_enum:to_int(type, multipart_request).


