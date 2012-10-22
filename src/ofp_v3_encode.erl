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
%% @doc OpenFlow Protocol 1.2 (3) encoding implementation.
%% @private
-module(ofp_v3_encode).

-export([do/1]).

-include("of_protocol.hrl").
-include("ofp_v3.hrl").

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

%% @doc Encode other structures
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

encode_struct(#ofp_packet_queue{queue_id = Queue, port_no = Port,
                                properties = Props}) ->
    PropsBin = encode_list(Props),
    Length = ?PACKET_QUEUE_SIZE + size(PropsBin),
    <<Queue:32, Port:32, Length:16, 0:48, PropsBin/bytes>>;
encode_struct(#ofp_queue_prop_min_rate{rate = Rate}) ->
    PropertyInt = ofp_v3_enum:to_int(queue_properties, min_rate),
    <<PropertyInt:16, ?QUEUE_PROP_MIN_RATE_SIZE:16, 0:32, Rate:16, 0:48>>;
encode_struct(#ofp_queue_prop_max_rate{rate = Rate}) ->
    PropertyInt = ofp_v3_enum:to_int(queue_properties, max_rate),
    <<PropertyInt:16, ?QUEUE_PROP_MAX_RATE_SIZE:16, 0:32, Rate:16, 0:48>>;
encode_struct(#ofp_queue_prop_experimenter{experimenter = Experimenter,
                                           data = Data}) ->
    Length = ?QUEUE_PROP_EXPERIMENTER_SIZE + byte_size(Data),
    PropertyInt = ofp_v3_enum:to_int(queue_properties, experimenter),
    <<PropertyInt:16, Length:16, 0:32, Experimenter:32, 0:32, Data/bytes>>;

encode_struct(#ofp_match{fields = Fields}) ->
    FieldsBin = encode_list(Fields),
    FieldsLength = size(FieldsBin),
    Length = FieldsLength + ?MATCH_SIZE - 4,
    case FieldsLength of
        0 ->
            Padding = 32;
        _ ->
            Padding = (8 - (Length rem 8)) * 8
    end,
    <<1:16, Length:16, FieldsBin/bytes, 0:Padding>>;
encode_struct(#ofp_field{class = Class, name = Field, has_mask = HasMask,
                         value = Value, mask = Mask}) ->
    ClassInt = ofp_v3_enum:to_int(oxm_class, Class),
    %% TODO: Handle different classes
    FieldInt = ofp_v3_enum:to_int(oxm_ofb_match_fields, Field),
    BitLength = ofp_v3_map:tlv_length(Field),
    case Class of
        openflow_basic ->
            Value2 = ofp_utils:cut_bits(Value, BitLength);
        _ ->
            Value2 = Value
    end,
    case HasMask of
        true ->
            HasMaskInt = 1,
            case Class of
                openflow_basic ->
                    Mask2 = ofp_utils:cut_bits(Mask, BitLength);
                _ ->
                    Mask2 = Mask
            end,
            Rest = <<Value2/bytes, Mask2/bytes>>,
            Len2 = byte_size(Value2) * 2;
        false ->
            HasMaskInt = 0,
            Rest = <<Value2/bytes>>,
            Len2 = byte_size(Value2)
    end,
    <<ClassInt:16, FieldInt:7, HasMaskInt:1, Len2:8, Rest/bytes>>;

encode_struct(#ofp_instruction_goto_table{table_id = Table}) ->
    Type = ofp_v3_enum:to_int(instruction_type, goto_table),
    Length = ?INSTRUCTION_GOTO_TABLE_SIZE,
    <<Type:16, Length:16, Table:8, 0:24>>;
encode_struct(#ofp_instruction_write_metadata{metadata = Metadata,
                                              metadata_mask = MetaMask}) ->
    Type = ofp_v3_enum:to_int(instruction_type, write_metadata),
    Length = ?INSTRUCTION_WRITE_METADATA_SIZE,
    <<Type:16, Length:16, 0:32, Metadata:8/bytes, MetaMask:8/bytes>>;
encode_struct(#ofp_instruction_write_actions{actions = Actions}) ->
    Type = ofp_v3_enum:to_int(instruction_type, write_actions),
    ActionsBin = encode_list(Actions),
    Length = ?INSTRUCTION_WRITE_ACTIONS_SIZE + size(ActionsBin),
    <<Type:16, Length:16, 0:32, ActionsBin/bytes>>;
encode_struct(#ofp_instruction_apply_actions{actions = Actions}) ->
    Type = ofp_v3_enum:to_int(instruction_type, apply_actions),
    ActionsBin = encode_list(Actions),
    Length = ?INSTRUCTION_APPLY_ACTIONS_SIZE + size(ActionsBin),
    <<Type:16, Length:16, 0:32, ActionsBin/bytes>>;
encode_struct(#ofp_instruction_clear_actions{}) ->
    Type = ofp_v3_enum:to_int(instruction_type, clear_actions),
    Length = ?INSTRUCTION_CLEAR_ACTIONS_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_instruction_experimenter{experimenter = Experimenter,
                                            data = Data}) ->
    Type = ofp_v3_enum:to_int(instruction_type, experimenter),
    Length = ?INSTRUCTION_EXPERIMENTER_SIZE + byte_size(Data),
    <<Type:16, Length:16, Experimenter:32, Data/bytes>>;

encode_struct(#ofp_action_output{port = Port, max_len = MaxLen}) ->
    Type = ofp_v3_enum:to_int(action_type, output),
    Length = ?ACTION_OUTPUT_SIZE,
    PortInt = get_id(port_no, Port),
    MaxLenInt = get_id(buffer, MaxLen),
    <<Type:16, Length:16, PortInt:32, MaxLenInt:16, 0:48>>;
encode_struct(#ofp_action_group{group_id = Group}) ->
    Type = ofp_v3_enum:to_int(action_type, group),
    Length = ?ACTION_GROUP_SIZE,
    GroupInt = get_id(group, Group),
    <<Type:16, Length:16, GroupInt:32>>;
encode_struct(#ofp_action_set_queue{queue_id = Queue}) ->
    Type = ofp_v3_enum:to_int(action_type, set_queue),
    QueueInt = get_id(queue, Queue),
    Length = ?ACTION_SET_QUEUE_SIZE,
    <<Type:16, Length:16, QueueInt:32>>;
encode_struct(#ofp_action_set_mpls_ttl{mpls_ttl = TTL}) ->
    Type = ofp_v3_enum:to_int(action_type, set_mpls_ttl),
    Length = ?ACTION_SET_MPLS_TTL_SIZE,
    <<Type:16, Length:16, TTL:8, 0:24>>;
encode_struct(#ofp_action_dec_mpls_ttl{}) ->
    Type = ofp_v3_enum:to_int(action_type, dec_mpls_ttl),
    Length = ?ACTION_DEC_MPLS_TTL_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_set_nw_ttl{nw_ttl = TTL}) ->
    Type = ofp_v3_enum:to_int(action_type, set_nw_ttl),
    Length = ?ACTION_SET_NW_TTL_SIZE,
    <<Type:16, Length:16, TTL:8, 0:24>>;
encode_struct(#ofp_action_dec_nw_ttl{}) ->
    Type = ofp_v3_enum:to_int(action_type, dec_nw_ttl),
    Length = ?ACTION_DEC_NW_TTL_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_copy_ttl_out{}) ->
    Type = ofp_v3_enum:to_int(action_type, copy_ttl_out),
    Length = ?ACTION_COPY_TTL_OUT_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_copy_ttl_in{}) ->
    Type = ofp_v3_enum:to_int(action_type, copy_ttl_in),
    Length = ?ACTION_COPY_TTL_IN_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_push_vlan{ethertype = EtherType}) ->
    Type = ofp_v3_enum:to_int(action_type, push_vlan),
    Length = ?ACTION_PUSH_VLAN_SIZE,
    <<Type:16, Length:16, EtherType:16, 0:16>>;
encode_struct(#ofp_action_pop_vlan{}) ->
    Type = ofp_v3_enum:to_int(action_type, pop_vlan),
    Length = ?ACTION_POP_VLAN_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_push_mpls{ethertype = EtherType}) ->
    Type = ofp_v3_enum:to_int(action_type, push_mpls),
    Length = ?ACTION_PUSH_MPLS_SIZE,
    <<Type:16, Length:16, EtherType:16, 0:16>>;
encode_struct(#ofp_action_pop_mpls{ethertype = EtherType}) ->
    Type = ofp_v3_enum:to_int(action_type, pop_mpls),
    Length = ?ACTION_POP_MPLS_SIZE,
    <<Type:16, Length:16, EtherType:16, 0:16>>;
encode_struct(#ofp_action_set_field{field = Field}) ->
    Type = ofp_v3_enum:to_int(action_type, set_field),
    FieldBin = encode_struct(Field),
    FieldSize = size(FieldBin),
    PartialLength = ?ACTION_SET_FIELD_SIZE - 4 + FieldSize,
    Padding = ofp_utils:padding(PartialLength, 8),
    Length = PartialLength + Padding,
    <<Type:16, Length:16, FieldBin/bytes, 0:(Padding*8)>>;
encode_struct(#ofp_action_experimenter{experimenter = Experimenter,
                                       data = Data}) ->
    Type = ofp_v3_enum:to_int(action_type, experimenter),
    Length = ?ACTION_EXPERIMENTER_SIZE + byte_size(Data),
    <<Type:16, Length:16, Experimenter:32, Data/bytes>>;

encode_struct(#ofp_bucket{weight = Weight, watch_port = Port,
                          watch_group = Group, actions = Actions}) ->
    ActionsBin = encode_list(Actions),
    Length = ?BUCKET_SIZE + size(ActionsBin),
    <<Length:16, Weight:16, Port:32, Group:32, 0:32, ActionsBin/bytes>>;
encode_struct(#ofp_flow_stats{table_id = Table, duration_sec = Sec,
                              duration_nsec = NSec, priority = Priority,
                              idle_timeout = Idle, hard_timeout = Hard,
                              cookie = Cookie, packet_count = PCount,
                              byte_count = BCount, match = Match,
                              instructions = Instructions}) ->
    MatchBin = encode_struct(Match),
    InstrsBin = encode_list(Instructions),
    Length = ?FLOW_STATS_SIZE + size(MatchBin) - ?MATCH_SIZE + size(InstrsBin),
    <<Length:16, Table:8, 0:8, Sec:32, NSec:32, Priority:16, Idle:16, Hard:16,
      0:48, Cookie:8/bytes, PCount:64, BCount:64, MatchBin/bytes,
      InstrsBin/bytes>>;
encode_struct(#ofp_table_stats{table_id = Table, name = Name,
                               match = Match, wildcards = Wildcards,
                               write_actions = WriteActions,
                               apply_actions = ApplyActions,
                               write_setfields = WriteSet,
                               apply_setfields = ApplySet,
                               metadata_match = MetaMatch,
                               metadata_write = MetaWrite,
                               instructions = Instructions, config = Config,
                               max_entries = Max, active_count = ACount,
                               lookup_count = LCount,
                               matched_count = MCount}) ->
    Padding = (?OFP_MAX_TABLE_NAME_LEN - size(Name)) * 8,
    MatchBin = flags_to_binary(oxm_ofb_match_fields, Match, 8),
    WildcardsBin = flags_to_binary(oxm_ofb_match_fields, Wildcards, 8),
    WriteActionsBin = flags_to_binary(action_type, WriteActions, 4),
    ApplyActionsBin = flags_to_binary(action_type, ApplyActions, 4),
    WriteSetBin = flags_to_binary(oxm_ofb_match_fields, WriteSet, 8),
    ApplySetBin = flags_to_binary(oxm_ofb_match_fields, ApplySet, 8),
    InstructionsBin = flags_to_binary(instruction_type, Instructions, 4),
    ConfigInt = ofp_v3_enum:to_int(table_config, Config),
    <<Table:8, 0:56, Name/bytes, 0:Padding, MatchBin:8/bytes,
      WildcardsBin:8/bytes, WriteActionsBin:4/bytes, ApplyActionsBin:4/bytes,
      WriteSetBin:8/bytes, ApplySetBin/bytes, MetaMatch:8/bytes,
      MetaWrite:8/bytes, InstructionsBin:4/bytes, ConfigInt:32, Max:32,
      ACount:32, LCount:64, MCount:64>>;
encode_struct(#ofp_port_stats{port_no = Port,
                              rx_packets = RXPackets, tx_packets = TXPackets,
                              rx_bytes = RXBytes, tx_bytes = TXBytes,
                              rx_dropped = RXDropped, tx_dropped = TXDropped,
                              rx_errors = RXErrors, tx_errors = TXErrors,
                              rx_frame_err = FrameErr, rx_over_err = OverErr,
                              rx_crc_err = CRCErr, collisions = Collisions}) ->
    PortInt = get_id(port_no, Port),
    <<PortInt:32, 0:32, RXPackets:64,
      TXPackets:64, RXBytes:64, TXBytes:64,
      RXDropped:64, TXDropped:64, RXErrors:64,
      TXErrors:64, FrameErr:64, OverErr:64,
      CRCErr:64, Collisions:64>>;
encode_struct(#ofp_queue_stats{port_no = Port, queue_id = Queue,
                               tx_bytes = Bytes, tx_packets = Packets,
                               tx_errors = Errors}) ->
    <<Port:32, Queue:32, Bytes:64, Packets:64, Errors:64>>;
encode_struct(#ofp_group_stats{group_id = Group, ref_count = RefCount,
                               packet_count = PCount, byte_count = BCount,
                               bucket_stats = Buckets}) ->
    GroupInt = get_id(group, Group),
    BucketsBin = encode_list(Buckets),
    Length = ?GROUP_STATS_SIZE + size(BucketsBin),
    <<Length:16, 0:16, GroupInt:32,
      RefCount:32, 0:32, PCount:64,
      BCount:64, BucketsBin/bytes>>;
encode_struct(#ofp_bucket_counter{packet_count = PCount,
                                  byte_count = BCount}) ->
    <<PCount:64, BCount:64>>;
encode_struct(#ofp_group_desc_stats{type = Type, group_id = Group,
                                    buckets = Buckets}) ->
    TypeInt = ofp_v3_enum:to_int(group_type, Type),
    GroupInt = get_id(group, Group),
    BucketsBin = encode_list(Buckets),
    Length = ?GROUP_DESC_STATS_SIZE + size(BucketsBin),
    <<Length:16, TypeInt:8, 0:8, GroupInt:32, BucketsBin/bytes>>.

%%% Messages -------------------------------------------------------------------

encode_body(#ofp_hello{}) ->
    <<>>;
encode_body(#ofp_error_msg{type = Type, code = Code, data = Data}) ->
    TypeInt = ofp_v3_enum:to_int(error_type, Type),
    CodeInt = ofp_v3_enum:to_int(Type, Code),
    <<TypeInt:16, CodeInt:16, Data/bytes>>;
encode_body(#ofp_error_msg_experimenter{exp_type = ExpTypeInt,
                                        experimenter = Experimenter,
                                        data = Data}) ->
    TypeInt = ofp_v3_enum:to_int(error_type, experimenter),
    <<TypeInt:16, ExpTypeInt:16, Experimenter:32, Data/bytes>>;
encode_body(#ofp_echo_request{data = Data}) ->
    Data;
encode_body(#ofp_echo_reply{data = Data}) ->
    Data;
encode_body(#ofp_experimenter{experimenter = Experimenter,
                              exp_type = Type, data = Data}) ->
    <<Experimenter:32, Type:32, Data/bytes>>;
encode_body(#ofp_features_request{}) ->
    <<>>;
encode_body(#ofp_features_reply{datapath_mac = DataPathMac,
                                datapath_id = DataPathID, n_buffers = NBuffers,
                                n_tables = NTables, capabilities = Capabilities,
                                ports = Ports}) ->
    PortsBin = encode_list(Ports),
    CapaBin = flags_to_binary(capabilities, Capabilities, 4),
    <<DataPathMac:6/bytes, DataPathID:16, NBuffers:32, NTables:8,
      0:24, CapaBin:4/bytes, 0:32, PortsBin/bytes>>;
encode_body(#ofp_get_config_request{}) ->
    <<>>;
encode_body(#ofp_get_config_reply{flags = Flags, miss_send_len = Miss}) ->
    FlagsBin = flags_to_binary(config_flags, Flags, 2),
    <<FlagsBin:2/bytes, Miss:16>>;
encode_body(#ofp_set_config{flags = Flags, miss_send_len = Miss}) ->
    FlagsBin = flags_to_binary(config_flags, Flags, 2),
    <<FlagsBin:2/bytes, Miss:16>>;
encode_body(#ofp_packet_in{buffer_id = BufferId, reason = Reason,
                           table_id = TableId, match = Match, data = Data}) ->
    BufferIdInt = get_id(buffer, BufferId),
    ReasonInt = ofp_v3_enum:to_int(packet_in_reason, Reason),
    MatchBin = encode_struct(Match),
    TotalLen = byte_size(Data),
    <<BufferIdInt:32, TotalLen:16, ReasonInt:8, TableId:8,
      MatchBin/bytes, 0:16, Data/bytes>>;
encode_body(#ofp_flow_removed{cookie = Cookie, priority = Priority,
                              reason = Reason, table_id = TableId,
                              duration_sec = Sec, duration_nsec = NSec,
                              idle_timeout = Idle, hard_timeout = Hard,
                              packet_count = PCount, byte_count = BCount,
                              match = Match}) ->
    ReasonInt = ofp_v3_enum:to_int(flow_removed_reason, Reason),
    MatchBin = encode_struct(Match),
    <<Cookie:8/bytes, Priority:16, ReasonInt:8, TableId:8, Sec:32, NSec:32,
      Idle:16, Hard:16, PCount:64, BCount:64, MatchBin/bytes>>;
encode_body(#ofp_port_status{reason = Reason, desc = Port}) ->
    ReasonInt = ofp_v3_enum:to_int(port_reason, Reason),
    PortBin = encode_struct(Port),
    <<ReasonInt:8, 0:56, PortBin/bytes>>;
encode_body(#ofp_queue_get_config_request{port = Port}) ->
    PortInt = get_id(port_no, Port),
    <<PortInt:32, 0:32>>;
encode_body(#ofp_queue_get_config_reply{port = Port, queues = Queues}) ->
    PortInt = get_id(port_no, Port),
    QueuesBin = encode_list(Queues),
    <<PortInt:32, 0:32, QueuesBin/bytes>>;
encode_body(#ofp_packet_out{buffer_id = BufferId, in_port = Port,
                            actions = Actions, data = Data}) ->
    BufferIdInt = get_id(buffer, BufferId),
    PortInt = get_id(port_no, Port),
    ActionsBin = encode_list(Actions),
    ActionsLength = size(ActionsBin),
    <<BufferIdInt:32, PortInt:32,
      ActionsLength:16, 0:48, ActionsBin/bytes, Data/bytes>>;
encode_body(#ofp_flow_mod{cookie = Cookie, cookie_mask = CookieMask,
                          table_id = Table, command = Command,
                          idle_timeout = Idle, hard_timeout = Hard,
                          priority = Priority, buffer_id = Buffer,
                          out_port = OutPort, out_group = OutGroup,
                          flags = Flags, match = Match,
                          instructions = Instructions}) ->
    TableInt = get_id(table, Table),
    BufferInt = get_id(buffer, Buffer),
    CommandInt = ofp_v3_enum:to_int(flow_mod_command, Command),
    OutPortInt = get_id(port_no, OutPort),
    OutGroupInt = get_id(group, OutGroup),
    FlagsBin = flags_to_binary(flow_mod_flags, Flags, 2),
    MatchBin = encode_struct(Match),
    InstructionsBin = encode_list(Instructions),
    <<Cookie:8/bytes, CookieMask:8/bytes, TableInt:8, CommandInt:8,
      Idle:16, Hard:16, Priority:16, BufferInt:32, OutPortInt:32,
      OutGroupInt:32, FlagsBin:2/bytes, 0:16, MatchBin/bytes,
      InstructionsBin/bytes>>;
encode_body(#ofp_group_mod{command = Command, type = Type,
                           group_id = Group, buckets = Buckets}) ->
    CommandInt = ofp_v3_enum:to_int(group_mod_command, Command),
    TypeInt = ofp_v3_enum:to_int(group_type, Type),
    GroupInt = get_id(group, Group),
    BucketsBin = encode_list(Buckets),
    <<CommandInt:16, TypeInt:8, 0:8, GroupInt:32, BucketsBin/bytes>>;
encode_body(#ofp_port_mod{port_no = Port, hw_addr = Addr,
                          config = Config, mask = Mask, advertise = Advertise}) ->
    PortInt = get_id(port_no, Port),
    ConfigBin = flags_to_binary(port_config, Config, 4),
    MaskBin = flags_to_binary(port_config, Mask, 4),
    AdvertiseBin = flags_to_binary(port_features, Advertise, 4),
    <<PortInt:32, 0:32, Addr:6/bytes, 0:16, ConfigBin:4/bytes,
      MaskBin:4/bytes, AdvertiseBin:4/bytes, 0:32>>;
encode_body(#ofp_table_mod{table_id = Table, config = Config}) ->
    TableInt = get_id(table, Table),
    ConfigInt = ofp_v3_enum:to_int(table_config, Config),
    <<TableInt:8, 0:24, ConfigInt:32>>;
encode_body(#ofp_desc_stats_request{flags = Flags}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, desc),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32>>;
encode_body(#ofp_desc_stats_reply{flags = Flags, mfr_desc = MFR,
                                  hw_desc = HW, sw_desc = SW,
                                  serial_num = Serial, dp_desc = DP}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, desc),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
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
    TypeInt = ofp_v3_enum:to_int(stats_type, flow),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    TableInt = get_id(table, Table),
    PortInt = get_id(port_no, Port),
    GroupInt = get_id(group, Group),
    MatchBin = encode_struct(Match),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      TableInt:8, 0:24, PortInt:32,
      GroupInt:32, 0:32, Cookie:8/bytes, CookieMask:8/bytes,
      MatchBin/bytes>>;
encode_body(#ofp_flow_stats_reply{flags = Flags, stats = Stats}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, flow),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32, StatsBin/bytes>>;
encode_body(#ofp_aggregate_stats_request{flags = Flags,
                                         table_id = Table, out_port = Port,
                                         out_group = Group, cookie = Cookie,
                                         cookie_mask = CookieMask,
                                         match = Match}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, aggregate),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
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
    TypeInt = ofp_v3_enum:to_int(stats_type, aggregate),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      PCount:64, BCount:64, FCount:32, 0:32>>;
encode_body(#ofp_table_stats_request{flags = Flags}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, table),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32>>;
encode_body(#ofp_table_stats_reply{flags = Flags, stats = Stats}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, table),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_port_stats_request{flags = Flags, port_no = Port}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, port),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    PortInt = get_id(port_no, Port),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      PortInt:32, 0:32>>;
encode_body(#ofp_port_stats_reply{flags = Flags, stats = Stats}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, port),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_queue_stats_request{flags = Flags,
                                     port_no = Port, queue_id = Queue}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, queue),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    PortInt = get_id(port_no, Port),
    QueueInt = get_id(queue, Queue),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      PortInt:32, QueueInt:32>>;
encode_body(#ofp_queue_stats_reply{flags = Flags, stats = Stats}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, queue),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_group_stats_request{flags = Flags,
                                     group_id = Group}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, group),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    GroupInt = get_id(group, Group),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      GroupInt:32, 0:32>>;
encode_body(#ofp_group_stats_reply{flags = Flags, stats = Stats}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, group),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_group_desc_stats_request{flags = Flags}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, group_desc),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32>>;
encode_body(#ofp_group_desc_stats_reply{flags = Flags, stats = Stats}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, group_desc),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
    StatsBin = encode_list(Stats),
    <<TypeInt:16, FlagsBin/bytes, 0:32,
      StatsBin/bytes>>;
encode_body(#ofp_group_features_stats_request{flags = Flags}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, group_features),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32>>;
encode_body(#ofp_group_features_stats_reply{flags = Flags,
                                            types = Types,
                                            capabilities = Capabilities,
                                            max_groups = {Max1, Max2, Max3, Max4},
                                            actions = {Actions1, Actions2,
                                                       Actions3, Actions4}}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, group_features),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
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
encode_body(#ofp_experimenter_stats_request{flags = Flags,
                                            experimenter = Experimenter,
                                            exp_type = ExpType, data = Data}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, experimenter),
    FlagsBin = flags_to_binary(stats_request_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      Experimenter:32, ExpType:32, Data/bytes>>;
encode_body(#ofp_experimenter_stats_reply{flags = Flags,
                                          experimenter = Experimenter,
                                          exp_type = ExpType, data = Data}) ->
    TypeInt = ofp_v3_enum:to_int(stats_type, experimenter),
    FlagsBin = flags_to_binary(stats_reply_flags, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      Experimenter:32, ExpType:32, Data/bytes>>;
encode_body(#ofp_barrier_request{}) ->
    <<>>;
encode_body(#ofp_barrier_reply{}) ->
    <<>>;
encode_body(#ofp_role_request{role = Role, generation_id = Gen}) ->
    RoleInt = ofp_v3_enum:to_int(controller_role, Role),
    <<RoleInt:32, 0:32, Gen:64>>;
encode_body(#ofp_role_reply{role = Role, generation_id = Gen}) ->
    RoleInt = ofp_v3_enum:to_int(controller_role, Role),
    <<RoleInt:32, 0:32, Gen:64>>;
encode_body(Other) ->
    throw({bad_message, Other}).

%%------------------------------------------------------------------------------
%% Helper functions
%%------------------------------------------------------------------------------

-spec get_id(atom(), integer() | atom()) -> integer() | atom().
get_id(Enum, Value) ->
    ofp_utils:get_enum_value(ofp_v3_enum, Enum, Value).

-spec encode_list(list()) -> binary().
encode_list(List) ->
    ofp_utils:encode_list(fun encode_struct/1, List, <<>>).

-spec flags_to_binary(atom(), [atom()], integer()) -> binary().
flags_to_binary(Type, Flags, Size) ->
    ofp_utils:flags_to_binary(ofp_v3_enum, Type, Flags, Size).

type_int(#ofp_hello{}) ->
    ofp_v3_enum:to_int(type, hello);
type_int(#ofp_error_msg{}) ->
    ofp_v3_enum:to_int(type, error);
type_int(#ofp_error_msg_experimenter{}) ->
    ofp_v3_enum:to_int(type, error);
type_int(#ofp_echo_request{}) ->
    ofp_v3_enum:to_int(type, echo_request);
type_int(#ofp_echo_reply{}) ->
    ofp_v3_enum:to_int(type, echo_reply);
type_int(#ofp_experimenter{}) ->
    ofp_v3_enum:to_int(type, experimenter);
type_int(#ofp_features_request{}) ->
    ofp_v3_enum:to_int(type, features_request);
type_int(#ofp_features_reply{}) ->
    ofp_v3_enum:to_int(type, features_reply);
type_int(#ofp_get_config_request{}) ->
    ofp_v3_enum:to_int(type, get_config_request);
type_int(#ofp_get_config_reply{}) ->
    ofp_v3_enum:to_int(type, get_config_reply);
type_int(#ofp_set_config{}) ->
    ofp_v3_enum:to_int(type, set_config);
type_int(#ofp_packet_in{}) ->
    ofp_v3_enum:to_int(type, packet_in);
type_int(#ofp_flow_removed{}) ->
    ofp_v3_enum:to_int(type, flow_removed);
type_int(#ofp_port_status{}) ->
    ofp_v3_enum:to_int(type, port_status);
type_int(#ofp_queue_get_config_request{}) ->
    ofp_v3_enum:to_int(type, queue_get_config_request);
type_int(#ofp_queue_get_config_reply{}) ->
    ofp_v3_enum:to_int(type, queue_get_config_reply);
type_int(#ofp_packet_out{}) ->
    ofp_v3_enum:to_int(type, packet_out);
type_int(#ofp_flow_mod{}) ->
    ofp_v3_enum:to_int(type, flow_mod);
type_int(#ofp_group_mod{}) ->
    ofp_v3_enum:to_int(type, group_mod);
type_int(#ofp_port_mod{}) ->
    ofp_v3_enum:to_int(type, port_mod);
type_int(#ofp_table_mod{}) ->
    ofp_v3_enum:to_int(type, table_mod);
type_int(#ofp_desc_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_desc_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_flow_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_flow_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_aggregate_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_aggregate_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_table_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_table_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_port_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_port_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_queue_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_queue_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_group_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_group_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_group_desc_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_group_desc_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_group_features_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_group_features_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_experimenter_stats_request{}) ->
    ofp_v3_enum:to_int(type, stats_request);
type_int(#ofp_experimenter_stats_reply{}) ->
    ofp_v3_enum:to_int(type, stats_reply);
type_int(#ofp_barrier_request{}) ->
    ofp_v3_enum:to_int(type, barrier_request);
type_int(#ofp_barrier_reply{}) ->
    ofp_v3_enum:to_int(type, barrier_reply);
type_int(#ofp_role_request{}) ->
    ofp_v3_enum:to_int(type, role_request);
type_int(#ofp_role_reply{}) ->
    ofp_v3_enum:to_int(type, role_reply).
