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
%% @doc OpenFlow Protocol 1.2 (3) decoding implementation.
%% @private
-module(ofp_v3_decode).

-export([do/1]).

-include("of_protocol.hrl").
-include("ofp_v3.hrl").

%%------------------------------------------------------------------------------
%% API functions
%%------------------------------------------------------------------------------

%% @doc Actual decoding of the message.
-spec do(Binary :: binary()) -> ofp_message().
do(Binary) ->
    <<Version:8, TypeInt:8, _:16, XID:32, BodyBin/bytes >> = Binary,
    Type = ofp_v3_enum:to_atom(type, TypeInt),
    Body = decode_body(Type, BodyBin),
    #ofp_message{version = Version, xid = XID, body = Body}.

%%------------------------------------------------------------------------------
%% Decode functions
%%------------------------------------------------------------------------------

%% Structures ------------------------------------------------------------------

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

%% @doc Decode match structure
decode_match(Binary) ->
    PadFieldsLength = size(Binary) - ?MATCH_SIZE + 4,
    <<TypeInt:16, NoPadLength:16,
      PadFieldsBin:PadFieldsLength/bytes>> = Binary,
    FieldsBinLength = (NoPadLength - 4),
    Padding = (PadFieldsLength - FieldsBinLength) * 8,
    <<FieldsBin:FieldsBinLength/bytes, 0:Padding>> = PadFieldsBin,
    Fields = decode_match_fields(FieldsBin),
    Type = ofp_v3_enum:to_atom(match_type, TypeInt),
    #ofp_match{type = Type, oxm_fields = Fields}.

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
    Class = ofp_v3_enum:to_atom(oxm_class, ClassInt),
    Field = ofp_v3_enum:to_atom(oxm_ofb_match_fields, FieldInt),
    HasMask = (HasMaskInt =:= 1),
    case Class of
        openflow_basic ->
            BitLength = ofp_v3_map:tlv_length(Field);
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
                   field = Field,
                   has_mask = HasMask}, Rest}.

%% @doc Decode actions
-spec decode_actions(binary()) -> [ofp_action()].
decode_actions(Binary) ->
    decode_actions(Binary, []).

-spec decode_actions(binary(), [ofp_action()]) -> [ofp_action()].
decode_actions(<<>>, Actions) ->
    lists:reverse(Actions);
decode_actions(Binary, Actions) ->
    <<TypeInt:16, Length:16, Data/bytes>> = Binary,
    Type = ofp_v3_enum:to_atom(action_type, TypeInt),
    case Type of
        output ->
            <<PortInt:32, MaxLenInt:16,
              0:48, Rest/bytes>> = Data,
            Port = get_id(port_no, PortInt),
            MaxLen = get_id(buffer, MaxLenInt),
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
            <<TTL:8, 0:24, Rest/bytes>> = Data,
            Action = #ofp_action_set_mpls_ttl{mpls_ttl = TTL};
        dec_mpls_ttl ->
            <<0:32, Rest/bytes>> = Data,
            Action = #ofp_action_dec_mpls_ttl{};
        set_nw_ttl ->
            <<TTL:8, 0:24, Rest/bytes>> = Data,
            Action = #ofp_action_set_nw_ttl{nw_ttl = TTL};
        dec_nw_ttl ->
            <<0:32, Rest/bytes>> = Data,
            Action = #ofp_action_dec_nw_ttl{};
        copy_ttl_out ->
            <<0:32, Rest/bytes>> = Data,
            Action = #ofp_action_copy_ttl_out{};
        copy_ttl_in ->
            <<0:32, Rest/bytes>> = Data,
            Action = #ofp_action_copy_ttl_in{};
        push_vlan ->
            <<EtherType:16, 0:16, Rest/bytes>> = Data,
            Action = #ofp_action_push_vlan{ethertype = EtherType};
        pop_vlan ->
            <<0:32, Rest/bytes>> = Data,
            Action = #ofp_action_pop_vlan{};
        push_mpls ->
            <<EtherType:16, 0:16, Rest/bytes>> = Data,
            Action = #ofp_action_push_mpls{ethertype = EtherType};
        pop_mpls ->
            <<EtherType:16, 0:16, Rest/bytes>> = Data,
            Action = #ofp_action_pop_mpls{ethertype = EtherType};
        set_field ->
            FieldLength = Length - 4,
            <<FieldBin:FieldLength/bytes, Rest/bytes>> = Data,
            {Field, _Padding} = decode_match_field(FieldBin),
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
    Type = ofp_v3_enum:to_atom(instruction_type, TypeInt),
    case Type of
        goto_table ->
            <<Table:8, 0:24, Rest/bytes>> = Data,
            Instruction = #ofp_instruction_goto_table{table_id = Table};
        write_metadata ->
            <<0:32, Metadata:8/bytes, MetaMask:8/bytes,
              Rest/bytes>> = Data,
            Instruction = #ofp_instruction_write_metadata{
              metadata = Metadata,
              metadata_mask = MetaMask};
        write_actions ->
            ActionsLength = Length - ?INSTRUCTION_WRITE_ACTIONS_SIZE,
            <<0:32, ActionsBin:ActionsLength/bytes,
              Rest/bytes>> = Data,
            Actions = decode_actions(ActionsBin),
            Instruction = #ofp_instruction_write_actions{actions = Actions};
        apply_actions ->
            ActionsLength = Length - ?INSTRUCTION_APPLY_ACTIONS_SIZE,
            <<0:32, ActionsBin:ActionsLength/bytes,
              Rest/bytes>> = Data,
            Actions = decode_actions(ActionsBin),
            Instruction = #ofp_instruction_apply_actions{actions = Actions};
        clear_actions ->
            <<0:32, Rest/bytes>> = Data,
            Instruction = #ofp_instruction_clear_actions{};
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
      0:32, Data/bytes>> = Binary,
    ActionsLength = Length - ?BUCKET_SIZE,
    <<ActionsBin:ActionsLength/bytes, Rest/bytes>> = Data,
    Actions = decode_actions(ActionsBin),
    Bucket = #ofp_bucket{weight = Weight, watch_port = Port, watch_group = Group,
                         actions = Actions},
    decode_buckets(Rest, [Bucket | Buckets]).

decode_flow_stats(Binary) ->
    <<_:16, Table:8, _:8, Sec:32, NSec:32, Priority:16, Idle:16, Hard:16,
      _:48, Cookie:8/bytes, PCount:64, BCount:64, Data/bytes>> = Binary,
    <<_:16, MatchLength:16, _/bytes>> = Data,
    MatchLengthPad = MatchLength + (8 - (MatchLength rem 8)),
    <<MatchBin:MatchLengthPad/bytes, InstrsBin/bytes>> = Data,
    Match = decode_match(MatchBin),
    Instrs = decode_instructions(InstrsBin),
    #ofp_flow_stats{table_id = Table, duration_sec = Sec, duration_nsec = NSec,
                    priority = Priority, idle_timeout = Idle,
                    hard_timeout = Hard, cookie = Cookie,
                    packet_count = PCount, byte_count = BCount,
                    match = Match, instructions = Instrs}.

decode_flow_stats_list(Binary) ->
    decode_flow_stats_list(Binary, []).

decode_flow_stats_list(<<>>, FlowStatsList) ->
    lists:reverse(FlowStatsList);
decode_flow_stats_list(Binary, FlowStatsList) ->
    <<Length:16, _/bytes>> = Binary,
    <<FlowStatsBin:Length/bytes, Rest/bytes>> = Binary,
    FlowStats = decode_flow_stats(FlowStatsBin),
    decode_flow_stats_list(Rest, [FlowStats | FlowStatsList]).

decode_table_stats(Binary) ->
    <<TableInt:8, 0:56, NameBin:?OFP_MAX_TABLE_NAME_LEN/bytes,
      MatchBin:8/bytes, WildcardsBin:8/bytes, WriteActionsBin:4/bytes,
      ApplyActionsBin:4/bytes, WriteSetBin:8/bytes, ApplySetBin:8/bytes,
      MetaMatch:8/bytes, MetaWrite:8/bytes, InstructionsBin:4/bytes,
      ConfigInt:32, Max:32, ACount:32, LCount:64,
      MCount:64>> = Binary,
    Table = get_id(table, TableInt),
    Name = ofp_utils:strip_string(NameBin),
    Match = binary_to_flags(oxm_ofb_match_fields, MatchBin),
    Wildcards = binary_to_flags(oxm_ofb_match_fields, WildcardsBin),
    WriteActions = binary_to_flags(action_type, WriteActionsBin),
    ApplyActions = binary_to_flags(action_type, ApplyActionsBin),
    WriteSet = binary_to_flags(oxm_ofb_match_fields, WriteSetBin),
    ApplySet = binary_to_flags(oxm_ofb_match_fields, ApplySetBin),
    Instructions = binary_to_flags(instruction_type, InstructionsBin),
    Config = ofp_v3_enum:to_atom(table_config, ConfigInt),
    #ofp_table_stats{table_id = Table, name = Name, match = Match,
                     wildcards = Wildcards, write_actions = WriteActions,
                     apply_actions = ApplyActions,
                     write_setfields = WriteSet, apply_setfields = ApplySet,
                     metadata_match = MetaMatch, metadata_write = MetaWrite,
                     instructions = Instructions, config = Config,
                     max_entries = Max, active_count = ACount,
                     lookup_count = LCount, matched_count = MCount}.

decode_port_stats(Binary) ->
    <<PortInt:32, 0:32, RXPackets:64,
      TXPackets:64, RXBytes:64, TXBytes:64,
      RXDropped:64, TXDropped:64, RXErrors:64,
      TXErrors:64, FrameErr:64, OverErr:64,
      CRCErr:64, Collisions:64>> = Binary,
    Port = get_id(port_no, PortInt),
    #ofp_port_stats{port_no = Port,
                    rx_packets = RXPackets, tx_packets = TXPackets,
                    rx_bytes = RXBytes, tx_bytes = TXBytes,
                    rx_dropped = RXDropped, tx_dropped = TXDropped,
                    rx_errors = RXErrors, tx_errors = TXErrors,
                    rx_frame_err = FrameErr, rx_over_err = OverErr,
                    rx_crc_err = CRCErr, collisions = Collisions}.

decode_queue_stats(Binary) ->
    <<PortInt:32, QueueInt:32, Bytes:64,
      Packets:64, Errors:64>> = Binary,
    Port = get_id(port_no, PortInt),
    Queue = get_id(queue, QueueInt),
    #ofp_queue_stats{port_no = Port, queue_id = Queue, tx_bytes = Bytes,
                     tx_packets = Packets, tx_errors = Errors}.

decode_group_stats(Binary) ->
    <<_:16, 0:16, GroupInt:32, RefCount:32,
      0:32, PCount:64, BCount:64,
      BucketsBin/bytes>> = Binary,
    Group = get_id(group, GroupInt),
    Buckets = decode_bucket_counters(BucketsBin),
    #ofp_group_stats{group_id = Group, ref_count = RefCount, packet_count = PCount,
                     byte_count = BCount, bucket_stats = Buckets}.

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
    <<_:16, TypeInt:8, 0:8,
      GroupInt:32, BucketsBin/bytes>> = Binary,
    Type = ofp_v3_enum:to_atom(group_type, TypeInt),
    Group = get_id(group, GroupInt),
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

%% @doc Actual decoding of the messages
-spec decode_body(atom(), binary()) -> ofp_message().
decode_body(hello, _) ->
    #ofp_hello{};
decode_body(error, Binary) ->
    <<TypeInt:16, More/bytes>> = Binary,
    Type = ofp_v3_enum:to_atom(error_type, TypeInt),
    case Type of
        experimenter ->
            DataLength = size(Binary) - ?ERROR_EXPERIMENTER_SIZE + ?OFP_HEADER_SIZE,
            <<ExpTypeInt:16, Experimenter:32,
              Data:DataLength/bytes>> = More,
            #ofp_error_experimenter{exp_type = ExpTypeInt,
                                    experimenter = Experimenter,
                                    data = Data};
        _ ->
            DataLength = size(Binary) - ?ERROR_SIZE + ?OFP_HEADER_SIZE,
            <<CodeInt:16, Data:DataLength/bytes>> = More,
            Code = ofp_v3_enum:to_atom(Type, CodeInt),
            #ofp_error{type = Type,
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
    PortsLength = size(Binary) - ?FEATURES_REPLY_SIZE + ?OFP_HEADER_SIZE,
    <<DataPathMac:6/bytes, DataPathID:16, NBuffers:32,
      NTables:8, 0:24, CapaBin:4/bytes, 0:32,
      PortsBin:PortsLength/bytes>> = Binary,
    Capabilities = binary_to_flags(capabilities, CapaBin),
    Ports = [decode_port(PortBin)
             || PortBin <- ofp_utils:split_binaries(PortsBin, ?PORT_SIZE)],
    #ofp_features_reply{datapath_mac = DataPathMac,
                        datapath_id = DataPathID, n_buffers = NBuffers,
                        n_tables = NTables, capabilities = Capabilities,
                        ports = Ports};
decode_body(get_config_request, _) ->
    #ofp_get_config_request{};
decode_body(get_config_reply, Binary) ->
    <<FlagsBin:2/bytes, Miss:16>> = Binary,
    Flags = binary_to_flags(config_flags, FlagsBin),
    #ofp_get_config_reply{flags = Flags,
                          miss_send_len = Miss};
decode_body(set_config, Binary) ->
    <<FlagsBin:2/bytes, Miss:16>> = Binary,
    Flags = binary_to_flags(config_flags, FlagsBin),
    #ofp_set_config{flags = Flags, miss_send_len = Miss};
decode_body(packet_in, Binary) ->
    <<BufferIdInt:32, TotalLen:16, ReasonInt:8,
      TableId:8, Tail/bytes>> = Binary,
    MatchLength = size(Binary) - (?PACKET_IN_SIZE - ?MATCH_SIZE)
        - 2 - TotalLen + ?OFP_HEADER_SIZE,
    <<MatchBin:MatchLength/bytes, 0:16, Payload/bytes>> = Tail,
    BufferId = get_id(buffer, BufferIdInt),
    Reason = ofp_v3_enum:to_atom(packet_in_reason, ReasonInt),
    Match = decode_match(MatchBin),
    <<Data:TotalLen/bytes>> = Payload,
    #ofp_packet_in{buffer_id = BufferId, reason = Reason,
                   table_id = TableId, match = Match, data = Data};
decode_body(flow_removed, Binary) ->
    MatchLength = size(Binary) - ?FLOW_REMOVED_SIZE + ?MATCH_SIZE
        + ?OFP_HEADER_SIZE,
    <<Cookie:8/bytes, Priority:16, ReasonInt:8,
      TableId:8, Sec:32, NSec:32, Idle:16,
      Hard:16, PCount:64, BCount:64,
      MatchBin:MatchLength/bytes>> = Binary,
    Reason = ofp_v3_enum:to_atom(flow_removed_reason, ReasonInt),
    Match = decode_match(MatchBin),
    #ofp_flow_removed{cookie = Cookie, priority = Priority,
                      reason = Reason, table_id = TableId, duration_sec = Sec,
                      duration_nsec = NSec, idle_timeout = Idle,
                      hard_timeout = Hard, packet_count = PCount,
                      byte_count = BCount, match = Match};
decode_body(port_status, Binary) ->
    <<ReasonInt:8, 0:56, PortBin:?PORT_SIZE/bytes>> = Binary,
    Reason = ofp_v3_enum:to_atom(port_reason, ReasonInt),
    Port = decode_port(PortBin),
    #ofp_port_status{reason = Reason, desc = Port};
decode_body(stats_request, Binary) ->
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      Data/bytes>> = Binary,
    Type = ofp_v3_enum:to_atom(stats_type, TypeInt),
    Flags = binary_to_flags(stats_request_flags, FlagsBin),
    case Type of
        desc ->
            #ofp_desc_stats_request{flags = Flags};
        flow ->
            MatchLength = size(Binary) - (?FLOW_STATS_REQUEST_SIZE - ?MATCH_SIZE) + ?OFP_HEADER_SIZE,
            <<TableInt:8, 0:24, PortInt:32,
              GroupInt:32, 0:32, Cookie:8/bytes,
              CookieMask:8/bytes, MatchBin:MatchLength/bytes>> = Data,
            Table = get_id(table, TableInt),
            Port = get_id(port_no, PortInt),
            Group = get_id(group, GroupInt),
            Match = decode_match(MatchBin),
            #ofp_flow_stats_request{flags = Flags,
                                    table_id = Table, out_port = Port,
                                    out_group = Group, cookie = Cookie,
                                    cookie_mask = CookieMask, match = Match};
        aggregate ->
            MatchLength = size(Binary) - (?AGGREGATE_STATS_REQUEST_SIZE - ?MATCH_SIZE) + ?OFP_HEADER_SIZE,
            <<TableInt:8, 0:24, PortInt:32,
              GroupInt:32, 0:32, Cookie:8/bytes,
              CookieMask:8/bytes, MatchBin:MatchLength/bytes>> = Data,
            Table = get_id(table, TableInt),
            Port = get_id(port_no, PortInt),
            Group = get_id(group, GroupInt),
            Match = decode_match(MatchBin),
            #ofp_aggregate_stats_request{flags = Flags,
                                         table_id = Table, out_port = Port,
                                         out_group = Group, cookie = Cookie,
                                         cookie_mask = CookieMask, match = Match};
        table ->
            #ofp_table_stats_request{flags = Flags};
        port ->
            <<PortInt:32, 0:32>> = Data,
            Port = get_id(port_no, PortInt),
            #ofp_port_stats_request{flags = Flags,
                                    port_no = Port};
        queue ->
            <<PortInt:32, QueueInt:32>> = Data,
            Port = get_id(port_no, PortInt),
            Queue = get_id(queue, QueueInt),
            #ofp_queue_stats_request{flags = Flags,
                                     port_no = Port, queue_id = Queue};
        group ->
            <<GroupInt:32, 0:32>> = Data,
            Group = get_id(group, GroupInt),
            #ofp_group_stats_request{flags = Flags,
                                     group_id = Group};
        group_desc ->
            #ofp_group_desc_stats_request{flags = Flags};
        group_features ->
            #ofp_group_features_stats_request{flags = Flags};
        experimenter ->
            DataLength = size(Binary) - ?EXPERIMENTER_STATS_REQUEST_SIZE + ?OFP_HEADER_SIZE,
            <<Experimenter:32, ExpType:32,
              ExpData:DataLength/bytes>> = Data,
            #ofp_experimenter_stats_request{flags = Flags,
                                            experimenter = Experimenter,
                                            exp_type = ExpType, data = ExpData}
    end;
decode_body(stats_reply, Binary) ->
    <<TypeInt:16, FlagsBin:2/bytes, 0:32,
      Data/bytes>> = Binary,
    Type = ofp_v3_enum:to_atom(stats_type, TypeInt),
    Flags = binary_to_flags(stats_reply_flag, FlagsBin),
    case Type of
        desc ->
            <<MFR:?DESC_STR_LEN/bytes, HW:?DESC_STR_LEN/bytes,
              SW:?DESC_STR_LEN/bytes, Serial:?SERIAL_NUM_LEN/bytes,
              DP:?DESC_STR_LEN/bytes>> = Data,
            #ofp_desc_stats_reply{flags = Flags,
                                  mfr_desc = ofp_utils:strip_string(MFR),
                                  hw_desc = ofp_utils:strip_string(HW),
                                  sw_desc = ofp_utils:strip_string(SW),
                                  serial_num = ofp_utils:strip_string(Serial),
                                  dp_desc = ofp_utils:strip_string(DP)};
        flow ->
            StatsLength = size(Binary) - ?FLOW_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = decode_flow_stats_list(StatsBin),
            #ofp_flow_stats_reply{flags = Flags,
                                  stats = Stats};
        aggregate ->
            <<PCount:64, BCount:64, FCount:32,
              0:32>> = Data,
            #ofp_aggregate_stats_reply{flags = Flags,
                                       packet_count = PCount,
                                       byte_count = BCount,
                                       flow_count = FCount};
        table ->
            StatsLength = size(Binary) - ?TABLE_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = [decode_table_stats(TStats)
                     || TStats <- ofp_utils:split_binaries(StatsBin,
                                                           ?TABLE_STATS_SIZE)],
            #ofp_table_stats_reply{flags = Flags,
                                   stats = Stats};
        port ->
            StatsLength = size(Binary) - ?PORT_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = [decode_port_stats(PStats)
                     || PStats <- ofp_utils:split_binaries(StatsBin,
                                                           ?PORT_STATS_SIZE)],
            #ofp_port_stats_reply{flags = Flags,
                                  stats = Stats};
        queue ->
            StatsLength = size(Binary) - ?QUEUE_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = [decode_queue_stats(QStats)
                     || QStats <- ofp_utils:split_binaries(StatsBin,
                                                           ?QUEUE_STATS_SIZE)],
            #ofp_queue_stats_reply{flags = Flags,
                                   stats = Stats};
        group ->
            StatsLength = size(Binary) - ?GROUP_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = decode_group_stats_list(StatsBin),
            #ofp_group_stats_reply{flags = Flags,
                                   stats = Stats};
        group_desc ->
            StatsLength = size(Binary) - ?GROUP_DESC_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<StatsBin:StatsLength/bytes>> = Data,
            Stats = decode_group_desc_stats_list(StatsBin),
            #ofp_group_desc_stats_reply{flags = Flags,
                                        stats = Stats};
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
            #ofp_group_features_stats_reply{flags = Flags,
                                            types = Types,
                                            capabilities = Capabilities,
                                            max_groups = {Max1, Max2,
                                                          Max3, Max4},
                                            actions = {Actions1, Actions2,
                                                       Actions3, Actions4}};
        experimenter ->
            DataLength = size(Binary) - ?EXPERIMENTER_STATS_REPLY_SIZE +
                ?OFP_HEADER_SIZE,
            <<Experimenter:32, ExpType:32,
              ExpData:DataLength/bytes>> = Data,
            #ofp_experimenter_stats_reply{flags = Flags,
                                          experimenter = Experimenter,
                                          exp_type = ExpType, data = ExpData}
    end;
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
decode_body(packet_out, Binary) ->
    <<BufferIdInt:32, PortInt:32, ActionsLength:16,
      0:48, Binary2/bytes>> = Binary,
    DataLength = size(Binary) - ?PACKET_OUT_SIZE + ?OFP_HEADER_SIZE
        - ActionsLength,
    <<ActionsBin:ActionsLength/bytes, Data:DataLength/bytes>> = Binary2,
    BufferId = get_id(buffer, BufferIdInt),
    Port = get_id(port_no, PortInt),
    Actions = decode_actions(ActionsBin),
    #ofp_packet_out{buffer_id = BufferId, in_port = Port,
                    actions = Actions, data = Data};
decode_body(flow_mod, Binary) ->
    <<Cookie:8/bytes, CookieMask:8/bytes, TableInt:8, CommandInt:8,
      Idle:16, Hard:16, Priority:16, BufferInt:32, OutPortInt:32,
      OutGroupInt:32, FlagsBin:2/bytes, 0:16, Data/bytes>> = Binary,
    Table = get_id(table, TableInt),
    Buffer = get_id(buffer, BufferInt),
    Command = ofp_v3_enum:to_atom(flow_mod_command, CommandInt),
    OutPort = get_id(port_no, OutPortInt),
    OutGroup = get_id(group, OutGroupInt),
    Flags = binary_to_flags(flow_mod_flags, FlagsBin),
    <<_:16, MatchLength:16, _/bytes>> = Data,
    MatchLengthPad = MatchLength + (8 - (MatchLength rem 8)),
    <<MatchBin:MatchLengthPad/bytes, InstrBin/bytes>> = Data,
    Match = decode_match(MatchBin),
    Instructions = decode_instructions(InstrBin),
    #ofp_flow_mod{cookie = Cookie, cookie_mask = CookieMask,
                  table_id = Table, command = Command, idle_timeout = Idle,
                  hard_timeout = Hard, priority = Priority, buffer_id = Buffer,
                  out_port = OutPort, out_group = OutGroup, flags = Flags,
                  match = Match, instructions = Instructions};
decode_body(group_mod, Binary) ->
    BucketsLength = size(Binary) - ?GROUP_MOD_SIZE + ?OFP_HEADER_SIZE,
    <<CommandInt:16, TypeInt:8, 0:8,
      GroupInt:32, BucketsBin:BucketsLength/bytes>> = Binary,
    Command = ofp_v3_enum:to_atom(group_mod_command, CommandInt),
    Type = ofp_v3_enum:to_atom(group_type, TypeInt),
    Group = get_id(group, GroupInt),
    Buckets = decode_buckets(BucketsBin),
    #ofp_group_mod{command = Command, type = Type,
                   group_id = Group, buckets = Buckets};
decode_body(port_mod, Binary) ->
    <<PortInt:32, 0:32, Addr:6/bytes,
      0:16, ConfigBin:4/bytes, MaskBin:4/bytes,
      AdvertiseBin:4/bytes, 0:32>> = Binary,
    Port = get_id(port_no, PortInt),
    Config = binary_to_flags(port_config, ConfigBin),
    Mask = binary_to_flags(port_config, MaskBin),
    Advertise = binary_to_flags(port_features, AdvertiseBin),
    #ofp_port_mod{port_no = Port, hw_addr = Addr,
                  config = Config, mask = Mask, advertise = Advertise};
decode_body(table_mod, Binary) ->
    <<TableInt:8, 0:24, ConfigInt:32>> = Binary,
    Table = get_id(table, TableInt),
    Config = ofp_v3_enum:to_atom(table_config, ConfigInt),
    #ofp_table_mod{table_id = Table, config = Config};
decode_body(barrier_request, _) ->
    #ofp_barrier_request{};
decode_body(barrier_reply, _) ->
    #ofp_barrier_reply{};
decode_body(role_request, Binary) ->
    <<RoleInt:32, 0:32, Gen:64>> = Binary,
    Role = ofp_v3_enum:to_atom(controller_role, RoleInt),
    #ofp_role_request{role = Role, generation_id = Gen};
decode_body(role_reply, Binary) ->
    <<RoleInt:32, 0:32, Gen:64>> = Binary,
    Role = ofp_v3_enum:to_atom(controller_role, RoleInt),
    #ofp_role_reply{role = Role, generation_id = Gen}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-spec binary_to_flags(atom(), binary()) -> [atom()].
binary_to_flags(Type, Binary) ->
    BitSize = size(Binary) * 8,
    <<Integer:BitSize>> = Binary,
    binary_to_flags(Type, Integer, BitSize-1, []).

-spec binary_to_flags(atom(), integer(), integer(), [atom()]) -> [atom()].
binary_to_flags(Type, Integer, Bit, Flags) when Bit >= 0 ->
    case 0 /= (Integer band (1 bsl Bit)) of
        true ->
            Flag = ofp_v3_enum:to_atom(Type, Bit),
            binary_to_flags(Type, Integer, Bit - 1, [Flag | Flags]);
        false ->
            binary_to_flags(Type, Integer, Bit - 1, Flags)
    end;
binary_to_flags(_, _, _, Flags) ->
    lists:reverse(Flags).

get_id(Enum, Int) ->
    %% TODO: Check if it's not larger than max
    try
	ofp_v3_enum:to_atom(Enum, Int)
    catch
	throw:bad_enum ->
	    Int
    end.
