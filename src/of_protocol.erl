%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%%% @doc OpenFlow Protocol library module.
%%% @end
%%%-----------------------------------------------------------------------------
-module(of_protocol).

%% API
-export([encode/1, decode/1]).

-include("of_protocol.hrl").

-export_type([instruction/0,
              match/0,
              flow_mod/0,
              table_mod/0,
              port_mod/0,
              group_mod/0,
              packet_out/0,
              echo_request/0,
              echo_reply/0,
              barrier_request/0,
              desc_stats_request/0,
              desc_stats_reply/0,
              flow_stats_request/0,
              flow_stats_reply/0,
              aggregate_stats_request/0,
              aggregate_stats_reply/0,
              table_stats_request/0,
              table_stats_reply/0,
              port_stats_request/0,
              port_stats_reply/0,
              queue_stats_request/0,
              queue_stats_reply/0,
              group_stats_request/0,
              group_stats_reply/0,
              group_desc_stats_request/0,
              group_desc_stats_reply/0,
              group_features_stats_request/0,
              group_features_stats_reply/0,
              error_msg/0,
              table_config/0]).

-define(VERSION, 3).

%%%-----------------------------------------------------------------------------
%%% API functions
%%%-----------------------------------------------------------------------------

%% @doc Encode erlang representation to binary.
-spec encode(ofp_message()) -> binary() | {error, term()}.
encode(Message) ->
    try
        {ok, encode2(Message)}
    catch
        _:Exception ->
            {error, Exception}
    end.

%% @doc Decode binary to erlang representation.
-spec decode(binary()) -> {ok, ofp_message(), binary()} | {error, term()}.
decode(Binary) ->
    try
        << HeaderBin:8/binary, Rest/binary >> = Binary,
        {Header, Type, Length} = decode_header(HeaderBin),
        {Message, Leftovers} = decode(Type, Length, Header, Rest),
        {ok, Message, Leftovers}
    catch
        _:Exception ->
            {error, Exception}
    end.

%%%-----------------------------------------------------------------------------
%%% Actual encode/decode functions
%%%-----------------------------------------------------------------------------

%% @doc Encode header
encode_header(#ofp_header{experimental = Experimental, version = Version,
                          xid = Xid}, Type, Length) ->
    TypeInt = ofp_map:msg_type(Type),
    ExperimentalInt = case Experimental of
                          true ->
                              1;
                          false ->
                              0
                      end,
    << ExperimentalInt:1/integer, Version:7/integer, TypeInt:8/integer,
       Length:16/integer, Xid:32/integer >>.

%% @doc Encode queue property header
encode_queue_header(Property, Length) ->
    PropertyInt = ofp_map:queue_property(Property),
    << PropertyInt:16/integer, Length:16/integer, 0:32/integer >>.

%% @doc Encode other structures
encode_struct(#port{port_no = PortNo, hw_addr = HWAddr, name = Name,
                    config = Config, state = State, curr = Curr,
                    advertised = Advertised, supported = Supported,
                    peer = Peer, curr_speed = CurrSpeed,
                    max_speed = MaxSpeed}) ->
    PortNoInt = ofp_map:encode_port_number(PortNo),
    ConfigBin = flags_to_binary(port_config, Config, 4),
    StateBin = flags_to_binary(port_state, State, 4),
    CurrBin = flags_to_binary(port_feature, Curr, 4),
    AdvertisedBin = flags_to_binary(port_feature, Advertised, 4),
    SupportedBin = flags_to_binary(port_feature, Supported, 4),
    PeerBin = flags_to_binary(port_feature, Peer, 4),
    Padding = (?OFP_MAX_PORT_NAME_LEN - size(Name)) * 8,
    << PortNoInt:32/integer, 0:32/integer, HWAddr:6/binary, 0:16/integer,
       Name/binary, 0:Padding/integer, ConfigBin:4/binary, StateBin:4/binary,
       CurrBin:4/binary, AdvertisedBin:4/binary, SupportedBin:4/binary,
       PeerBin:4/binary, CurrSpeed:32/integer, MaxSpeed:32/integer >>;
encode_struct(#match{type = Type, oxm_fields = Fields}) ->
    TypeInt = ofp_map:match_type(Type),
    FieldsBin = encode_list(Fields),
    FieldsLength = size(FieldsBin),
    Length = FieldsLength + ?MATCH_SIZE - 4,
    case FieldsLength of
        0 ->
            Padding = 32;
        _ ->
            Padding = (8 - (Length rem 8)) * 8
    end,
    << TypeInt:16/integer, Length:16/integer, FieldsBin/binary,
       0:Padding/integer >>;
encode_struct(#oxm_field{class = Class, field = Field, has_mask = HasMask,
                         value = Value, mask = Mask}) ->
    ClassInt = ofp_map:oxm_class(Class),
    FieldInt = ofp_map:oxm_field(Class, Field),
    case Class of
        openflow_basic ->
            BitLength = ofp_map:tlv_length(Field),
            Length = (BitLength - 1) div 8 + 1;
        _ ->
            Length = size(Value),
            BitLength = Length * 8
    end,
    Value2 = cut(Value, BitLength),
    case HasMask of
        true ->
            HasMaskInt = 1,
            Mask2 = cut(Mask, BitLength),
            Rest = << Value2:Length/binary, Mask2:Length/binary >>,
            Len2 = Length * 2;
        false ->
            HasMaskInt = 0,
            Rest = << Value2:Length/binary >>,
            Len2 = Length
    end,
    << ClassInt:16/integer, FieldInt:7/integer, HasMaskInt:1/integer,
       Len2:8/integer, Rest/binary >>;
encode_struct(#action_output{port = Port, max_len = MaxLen}) ->
    Type = ofp_map:action_type(output),
    Length = ?ACTION_OUTPUT_SIZE,
    PortInt = ofp_map:encode_port_number(Port),
    MaxLenInt = ofp_map:encode_max_length(MaxLen),
    << Type:16/integer, Length:16/integer, PortInt:32/integer,
       MaxLenInt:16/integer, 0:48/integer >>;
encode_struct(#action_group{group_id = Group}) ->
    Type = ofp_map:action_type(group),
    Length = ?ACTION_GROUP_SIZE,
    GroupInt = ofp_map:encode_group_id(Group),
    << Type:16/integer, Length:16/integer, GroupInt:32/integer >>;
encode_struct(#action_set_queue{queue_id = Queue}) ->
    Type = ofp_map:action_type(set_queue),
    QueueInt = ofp_map:encode_queue_id(Queue),
    Length = ?ACTION_SET_QUEUE_SIZE,
    << Type:16/integer, Length:16/integer, QueueInt:32/integer >>;
encode_struct(#action_set_mpls_ttl{mpls_ttl = TTL}) ->
    Type = ofp_map:action_type(set_mpls_ttl),
    Length = ?ACTION_SET_MPLS_TTL_SIZE,
    << Type:16/integer, Length:16/integer, TTL:8/integer,
       0:24/integer >>;
encode_struct(#action_dec_mpls_ttl{}) ->
    Type = ofp_map:action_type(dec_mpls_ttl),
    Length = ?ACTION_DEC_MPLS_TTL_SIZE,
    << Type:16/integer, Length:16/integer, 0:32/integer >>;
encode_struct(#action_set_nw_ttl{nw_ttl = TTL}) ->
    Type = ofp_map:action_type(set_nw_ttl),
    Length = ?ACTION_SET_NW_TTL_SIZE,
    << Type:16/integer, Length:16/integer, TTL:8/integer,
       0:24/integer >>;
encode_struct(#action_dec_nw_ttl{}) ->
    Type = ofp_map:action_type(dec_nw_ttl),
    Length = ?ACTION_DEC_NW_TTL_SIZE,
    << Type:16/integer, Length:16/integer, 0:32/integer >>;
encode_struct(#action_copy_ttl_out{}) ->
    Type = ofp_map:action_type(copy_ttl_out),
    Length = ?ACTION_COPY_TTL_OUT_SIZE,
    << Type:16/integer, Length:16/integer, 0:32/integer >>;
encode_struct(#action_copy_ttl_in{}) ->
    Type = ofp_map:action_type(copy_ttl_in),
    Length = ?ACTION_COPY_TTL_IN_SIZE,
    << Type:16/integer, Length:16/integer, 0:32/integer >>;
encode_struct(#action_push_vlan{ethertype = EtherType}) ->
    Type = ofp_map:action_type(push_vlan),
    Length = ?ACTION_PUSH_VLAN_SIZE,
    << Type:16/integer, Length:16/integer, EtherType:16/integer,
       0:16/integer >>;
encode_struct(#action_pop_vlan{}) ->
    Type = ofp_map:action_type(pop_vlan),
    Length = ?ACTION_POP_VLAN_SIZE,
    << Type:16/integer, Length:16/integer, 0:32/integer >>;
encode_struct(#action_push_mpls{ethertype = EtherType}) ->
    Type = ofp_map:action_type(push_mpls),
    Length = ?ACTION_PUSH_MPLS_SIZE,
    << Type:16/integer, Length:16/integer, EtherType:16/integer,
       0:16/integer >>;
encode_struct(#action_pop_mpls{ethertype = EtherType}) ->
    Type = ofp_map:action_type(pop_mpls),
    Length = ?ACTION_POP_MPLS_SIZE,
    << Type:16/integer, Length:16/integer, EtherType:16/integer,
       0:16/integer >>;
encode_struct(#action_set_field{field = Field}) ->
    Type = ofp_map:action_type(set_field),
    FieldBin = encode_struct(Field),
    FieldSize = size(FieldBin),
    Padding = 8 - (?ACTION_SET_FIELD_SIZE - 4 + FieldSize) rem 8,
    Length = ?ACTION_SET_FIELD_SIZE - 4 + FieldSize + Padding,
    << Type:16/integer, Length:16/integer, FieldBin/binary,
       0:(Padding*8)/integer >>;
encode_struct(#action_experimenter{experimenter = Experimenter}) ->
    Type = ofp_map:action_type(experimenter),
    Length = ?ACTION_EXPERIMENTER_SIZE,
    << Type:16/integer, Length:16/integer, Experimenter:32/integer >>;
encode_struct(#instruction_goto_table{table_id = Table}) ->
    Type = ofp_map:instruction_type(goto_table),
    Length = ?INSTRUCTION_GOTO_TABLE_SIZE,
    TableInt = ofp_map:encode_table_id(Table),
    << Type:16/integer, Length:16/integer, TableInt:8/integer, 0:24/integer >>;
encode_struct(#instruction_write_metadata{metadata = Metadata,
                                          metadata_mask = MetaMask}) ->
    Type = ofp_map:instruction_type(write_metadata),
    Length = ?INSTRUCTION_WRITE_METADATA_SIZE,
    << Type:16/integer, Length:16/integer, 0:32/integer,
       Metadata:8/binary, MetaMask:8/binary >>;
encode_struct(#instruction_write_actions{actions = Actions}) ->
    Type = ofp_map:instruction_type(write_actions),
    ActionsBin = encode_list(Actions),
    Length = ?INSTRUCTION_WRITE_ACTIONS_SIZE + size(ActionsBin),
    << Type:16/integer, Length:16/integer, 0:32/integer, ActionsBin/binary >>;
encode_struct(#instruction_apply_actions{actions = Actions}) ->
    Type = ofp_map:instruction_type(apply_actions),
    ActionsBin = encode_list(Actions),
    Length = ?INSTRUCTION_APPLY_ACTIONS_SIZE + size(ActionsBin),
    << Type:16/integer, Length:16/integer, 0:32/integer, ActionsBin/binary >>;
encode_struct(#instruction_clear_actions{}) ->
    Type = ofp_map:instruction_type(clear_actions),
    Length = ?INSTRUCTION_CLEAR_ACTIONS_SIZE,
    << Type:16/integer, Length:16/integer, 0:32/integer >>;
encode_struct(#instruction_experimenter{experimenter = Experimenter}) ->
    Type = ofp_map:instruction_type(experimenter),
    Length = ?INSTRUCTION_EXPERIMENTER_SIZE,
    << Type:16/integer, Length:16/integer, Experimenter:32/integer >>;
encode_struct(#bucket{weight = Weight, watch_port = Port, watch_group = Group,
                      actions = Actions}) ->
    ActionsBin = encode_list(Actions),
    Length = ?BUCKET_SIZE + size(ActionsBin),
    << Length:16/integer, Weight:16/integer, Port:32/integer, Group:32/integer,
       0:32/integer, ActionsBin/binary >>;
encode_struct(#packet_queue{queue_id = Queue, port = Port,
                            properties = Props}) ->
    PropsBin = encode_list(Props),
    Length = ?PACKET_QUEUE_SIZE + size(PropsBin),
    << Queue:32/integer, Port:32/integer, Length:16/integer, 0:48/integer,
       PropsBin/binary >>;
encode_struct(#queue_prop_min_rate{rate = Rate}) ->
    HeaderBin = encode_queue_header(min_rate, ?QUEUE_PROP_MIN_RATE_SIZE),
    << HeaderBin/binary, Rate:16/integer, 0:48/integer >>;
encode_struct(#queue_prop_max_rate{rate = Rate}) ->
    HeaderBin = encode_queue_header(max_rate, ?QUEUE_PROP_MAX_RATE_SIZE),
    << HeaderBin/binary, Rate:16/integer, 0:48/integer >>;
encode_struct(#queue_prop_experimenter{experimenter = Experimenter,
                                       data = Data}) ->
    Length = ?QUEUE_PROP_EXPERIMENTER_SIZE + byte_size(Data),
    HeaderBin = encode_queue_header(experimenter, Length),
    << HeaderBin/binary, Experimenter:32/integer, 0:32/integer,
       Data/binary >>;
encode_struct(#flow_stats{table_id = Table, duration_sec = Sec,
                          duration_nsec = NSec, priority = Priority,
                          idle_timeout = Idle, hard_timeout = Hard,
                          cookie = Cookie, packet_count = PCount,
                          byte_count = BCount, match = Match,
                          instructions = Instructions}) ->
    TableInt = ofp_map:encode_table_id(Table),
    MatchBin = encode_struct(Match),
    InstrsBin = encode_list(Instructions),
    Length = ?FLOW_STATS_SIZE + size(MatchBin) - ?MATCH_SIZE + size(InstrsBin),
    << Length:16/integer, TableInt:8/integer, 0:8/integer, Sec:32/integer,
       NSec:32/integer, Priority:16/integer, Idle:16/integer, Hard:16/integer,
       0:48/integer, Cookie:8/binary, PCount:64/integer, BCount:64/integer,
       MatchBin/binary, InstrsBin/binary >>;
encode_struct(#table_stats{table_id = Table, name = Name, match = Match,
                           wildcards = Wildcards, write_actions = WriteActions,
                           apply_actions = ApplyActions,
                           write_setfields = WriteSet, apply_setfields = ApplySet,
                           metadata_match = MetaMatch, metadata_write = MetaWrite,
                           instructions = Instructions, config = Config,
                           max_entries = Max, active_count = ACount,
                           lookup_count = LCount, matched_count = MCount}) ->
    TableInt = ofp_map:encode_table_id(Table),
    Padding = (?OFP_MAX_TABLE_NAME_LEN - size(Name)) * 8,
    MatchBin = flags_to_binary(oxm_field, Match, 8),
    WildcardsBin = flags_to_binary(oxm_field, Wildcards, 8),
    WriteActionsBin = flags_to_binary(action_type, WriteActions, 4),
    ApplyActionsBin = flags_to_binary(action_type, ApplyActions, 4),
    WriteSetBin = flags_to_binary(oxm_field, WriteSet, 8),
    ApplySetBin = flags_to_binary(oxm_field, ApplySet, 8),
    InstructionsBin = flags_to_binary(instruction_type, Instructions, 4),
    ConfigInt = ofp_map:table_config(Config),
    << TableInt:8/integer, 0:56/integer, Name/binary, 0:Padding/integer,
       MatchBin/binary, WildcardsBin/binary, WriteActionsBin/binary,
       ApplyActionsBin/binary, WriteSetBin/binary, ApplySetBin/binary,
       MetaMatch:64/integer, MetaWrite:64/integer, InstructionsBin/binary,
       ConfigInt:32/integer, Max:32/integer, ACount:32/integer, LCount:64/integer,
       MCount:64/integer >>;
encode_struct(#port_stats{port_no = Port,
                          rx_packets = RXPackets, tx_packets = TXPackets,
                          rx_bytes = RXBytes, tx_bytes = TXBytes,
                          rx_dropped = RXDropped, tx_dropped = TXDropped,
                          rx_errors = RXErrors, tx_errors = TXErrors,
                          rx_frame_err = FrameErr, rx_over_err = OverErr,
                          rx_crc_err = CRCErr, collisions = Collisions}) ->
    PortInt = ofp_map:encode_port_number(Port),
    << PortInt:32/integer, 0:32/integer, RXPackets:64/integer,
       TXPackets:64/integer, RXBytes:64/integer, TXBytes:64/integer,
       RXDropped:64/integer, TXDropped:64/integer, RXErrors:64/integer,
       TXErrors:64/integer, FrameErr:64/integer, OverErr:64/integer,
       CRCErr:64/integer, Collisions:64/integer >>;
encode_struct(#queue_stats{port_no = Port, queue_id = Queue,
                           tx_bytes = Bytes, tx_packets = Packets,
                           tx_errors = Errors}) ->
    PortInt = ofp_map:encode_port_number(Port),
    QueueInt = ofp_map:encode_queue_id(Queue),
    << PortInt:32/integer, QueueInt:32/integer, Bytes:64/integer,
       Packets:64/integer, Errors:64/integer >>;
encode_struct(#group_stats{group_id = Group, ref_count = RefCount,
                           packet_count = PCount, byte_count = BCount,
                           bucket_stats = Buckets}) ->
    GroupInt = ofp_map:encode_group_id(Group),
    BucketsBin = encode_list(Buckets),
    Length = ?GROUP_STATS_SIZE + size(BucketsBin),
    << Length:16/integer, 0:16/integer, GroupInt:32/integer,
       RefCount:32/integer, 0:32/integer, PCount:64/integer,
       BCount:64/integer, BucketsBin/binary >>;
encode_struct(#bucket_counter{packet_count = PCount, byte_count = BCount}) ->
    << PCount:64/integer, BCount:64/integer >>;
encode_struct(#group_desc_stats{type = Type, group_id = Group,
                                buckets = Buckets}) ->
    TypeInt = ofp_map:group_type(Type),
    GroupInt = ofp_map:encode_group_id(Group),
    BucketsBin = encode_list(Buckets),
    Length = ?GROUP_DESC_STATS_SIZE + size(BucketsBin),
    << Length:16/integer, TypeInt:8/integer, 0:8/integer,
       GroupInt:32/integer, BucketsBin/binary >>.

%% @doc Actual encoding of the messages
encode2(#hello{header = Header}) ->
    HeaderBin = encode_header(Header, hello, ?OFP_HEADER_SIZE),
    << HeaderBin/binary >>;
encode2(#error_msg{header = Header, type = Type, code = Code, data = Data}) ->
    Length = size(Data) + ?ERROR_MSG_SIZE,
    HeaderBin = encode_header(Header, error, Length),
    TypeInt = ofp_map:error_type(Type),
    CodeInt = ofp_map:Type(Code),
    << HeaderBin/binary, TypeInt:16/integer, CodeInt:16/integer, Data/binary >>;
encode2(#error_experimenter_msg{header = Header, exp_type = ExpTypeInt,
                                experimenter = Experimenter, data = Data}) ->
    Length = size(Data) + ?ERROR_EXPERIMENTER_MSG_SIZE,
    HeaderBin = encode_header(Header, error, Length),
    TypeInt = ofp_map:error_type(experimenter),
    << HeaderBin/binary, TypeInt:16/integer, ExpTypeInt:16/integer,
       Experimenter:32/integer, Data/binary >>;
encode2(#echo_request{header = Header, data = Data}) ->
    Length = size(Data) + ?ECHO_REQUEST_SIZE,
    HeaderBin = encode_header(Header, echo_request, Length),
    << HeaderBin/binary, Data/binary >>;
encode2(#echo_reply{header = Header, data = Data}) ->
    Length = size(Data) + ?ECHO_REPLY_SIZE,
    HeaderBin = encode_header(Header, echo_reply, Length),
    << HeaderBin/binary, Data/binary >>;
encode2(#experimenter{header = Header, experimenter = Experimenter,
                      exp_type = Type, data = Data}) ->
    Length = ?EXPERIMENTER_SIZE + size(Data),
    HeaderBin = encode_header(Header, experimenter, Length),
    << HeaderBin/binary, Experimenter:32/integer, Type:32/integer,
       Data/binary >>;
encode2(#features_request{header = Header}) ->
    HeaderBin = encode_header(Header, features_request, ?FEATURES_REQUEST_SIZE),
    << HeaderBin/binary >>;
encode2(#features_reply{header = Header, datapath_mac = DataPathMac,
                        datapath_id = DataPathID, n_buffers = NBuffers,
                        n_tables = NTables, capabilities = Capabilities,
                        ports = Ports}) ->
    PortsBin = encode_list(Ports),
    CapaBin = flags_to_binary(capability, Capabilities, 4),
    Length = size(PortsBin) + ?FEATURES_REPLY_SIZE,
    HeaderBin = encode_header(Header, features_reply, Length),
    << HeaderBin/binary, DataPathMac:6/binary, DataPathID:16/integer,
       NBuffers:32/integer, NTables:8/integer, 0:24/integer, CapaBin:4/binary,
       0:32/integer, PortsBin/binary >>;
encode2(#get_config_request{header = Header}) ->
    HeaderBin = encode_header(Header, get_config_request,
                              ?GET_CONFIG_REQUEST_SIZE),
    << HeaderBin/binary >>;
encode2(#get_config_reply{header = Header, flags = Flags,
                          miss_send_len = Miss}) ->
    FlagsBin = flags_to_binary(configuration, Flags, 2),
    HeaderBin = encode_header(Header, get_config_reply,
                              ?GET_CONFIG_REPLY_SIZE),
    << HeaderBin/binary, FlagsBin:2/binary, Miss:16/integer >>;
encode2(#set_config{header = Header, flags = Flags, miss_send_len = Miss}) ->
    FlagsBin = flags_to_binary(configuration, Flags, 2),
    HeaderBin = encode_header(Header, set_config, ?SET_CONFIG_SIZE),
    << HeaderBin/binary, FlagsBin:2/binary, Miss:16/integer >>;
encode2(#packet_in{header = Header, buffer_id = BufferId, reason = Reason,
                   table_id = TableId, match = Match, data = Data}) ->
    ReasonInt = ofp_map:reason(Reason),
    MatchBin = encode_struct(Match),
    TotalLen = byte_size(Data),
    Length = (?PACKET_IN_SIZE - ?MATCH_SIZE) + 2 + size(MatchBin) + size(Data),
    HeaderBin = encode_header(Header, packet_in, Length),
    << HeaderBin/binary, BufferId:32/integer, TotalLen:16/integer,
       ReasonInt:8/integer, TableId:8/integer, MatchBin/binary,
       0:16, Data/binary >>;
encode2(#flow_removed{header = Header, cookie = Cookie, priority = Priority,
                      reason = Reason, table_id = TableId, duration_sec = Sec,
                      duration_nsec = NSec, idle_timeout = Idle,
                      hard_timeout = Hard, packet_count = PCount,
                      byte_count = BCount, match = Match}) ->
    ReasonInt = ofp_map:removed_reason(Reason),
    MatchBin = encode_struct(Match),
    Length = ?FLOW_REMOVED_SIZE + size(MatchBin) - ?MATCH_SIZE,
    HeaderBin = encode_header(Header, flow_removed, Length),
    << HeaderBin/binary, Cookie:8/binary, Priority:16/integer,
       ReasonInt:8/integer, TableId:8/integer, Sec:32/integer, NSec:32/integer,
       Idle:16/integer, Hard:16/integer, PCount:64/integer, BCount:64/integer,
       MatchBin/binary >>;
encode2(#port_status{header = Header, reason = Reason, desc = Port}) ->
    ReasonInt = ofp_map:port_reason(Reason),
    PortBin = encode_struct(Port),
    HeaderBin = encode_header(Header, port_status, ?PORT_STATUS_SIZE),
    << HeaderBin/binary, ReasonInt:8/integer, 0:56/integer, PortBin/binary >>;
encode2(#queue_get_config_request{header = Header, port = Port}) ->
    PortInt = ofp_map:encode_port_number(Port),
    HeaderBin = encode_header(Header, queue_get_config_request,
                              ?QUEUE_GET_CONFIG_REQUEST_SIZE),
    << HeaderBin/binary, PortInt:32/integer, 0:32/integer >>;
encode2(#queue_get_config_reply{header = Header, port = Port,
                                queues = Queues}) ->
    PortInt = ofp_map:encode_port_number(Port),
    QueuesBin = encode_list(Queues),
    Length = ?QUEUE_GET_CONFIG_REPLY_SIZE + size(QueuesBin),
    HeaderBin = encode_header(Header, queue_get_config_reply, Length),
    << HeaderBin/binary, PortInt:32/integer, 0:32/integer,
       QueuesBin/binary >>;
encode2(#packet_out{header = Header, buffer_id = BufferId, in_port = Port,
                    actions = Actions, data = Data}) ->
    PortInt = ofp_map:encode_port_number(Port),
    ActionsBin = encode_list(Actions),
    ActionsLength = size(ActionsBin),
    Length = ?PACKET_OUT_SIZE + ActionsLength + byte_size(Data),
    HeaderBin = encode_header(Header, packet_out, Length),
    << HeaderBin/binary, BufferId:32/integer, PortInt:32/integer,
       ActionsLength:16/integer, 0:48/integer, ActionsBin/binary,
       Data/binary >>;
encode2(#flow_mod{header = Header, cookie = Cookie, cookie_mask = CookieMask,
                  table_id = Table, command = Command, idle_timeout = Idle,
                  hard_timeout = Hard, priority = Priority, buffer_id = Buffer,
                  out_port = OutPort, out_group = OutGroup, flags = Flags,
                  match = Match, instructions = Instructions}) ->
    TableInt = ofp_map:encode_table_id(Table),
    CommandInt = ofp_map:flow_command(Command),
    OutPortInt = ofp_map:encode_port_number(OutPort),
    OutGroupInt = ofp_map:encode_group_id(OutGroup),
    FlagsBin = flags_to_binary(flow_flag, Flags, 2),
    MatchBin = encode_struct(Match),
    InstructionsBin = encode_list(Instructions),
    Length = ?FLOW_MOD_SIZE + size(MatchBin) +
        size(InstructionsBin) - ?MATCH_SIZE,
    HeaderBin = encode_header(Header, flow_mod, Length),
    << HeaderBin/binary, Cookie:8/binary, CookieMask:8/binary,
       TableInt:8/integer, CommandInt:8/integer, Idle:16/integer, Hard:16/integer,
       Priority:16/integer, Buffer:32/integer, OutPortInt:32/integer,
       OutGroupInt:32/integer, FlagsBin:2/binary, 0:16/integer,
       MatchBin/binary, InstructionsBin/binary >>;
encode2(#group_mod{header = Header, command = Command, type = Type,
                   group_id = Group, buckets = Buckets}) ->
    CommandInt = ofp_map:group_command(Command),
    TypeInt = ofp_map:group_type(Type),
    GroupInt = ofp_map:encode_group_id(Group),
    BucketsBin = encode_list(Buckets),
    Length = ?GROUP_MOD_SIZE + size(BucketsBin),
    HeaderBin = encode_header(Header, group_mod, Length),
    << HeaderBin/binary, CommandInt:16/integer, TypeInt:8/integer, 0:8/integer,
       GroupInt:32/integer, BucketsBin/binary >>;
encode2(#port_mod{header = Header, port_no = Port, hw_addr = Addr,
                  config = Config, mask = Mask, advertise = Advertise}) ->
    PortInt = ofp_map:encode_port_number(Port),
    ConfigBin = flags_to_binary(port_config, Config, 4),
    MaskBin = flags_to_binary(port_config, Mask, 4),
    AdvertiseBin = flags_to_binary(port_feature, Advertise, 4),
    HeaderBin = encode_header(Header, port_mod, ?PORT_MOD_SIZE),
    << HeaderBin/binary, PortInt:32/integer, 0:32/integer, Addr:6/binary,
       0:16/integer, ConfigBin:4/binary, MaskBin:4/binary,
       AdvertiseBin:4/binary, 0:32/integer >>;
encode2(#table_mod{header = Header, table_id = Table, config = Config}) ->
    TableInt = ofp_map:encode_table_id(Table),
    ConfigInt = ofp_map:table_config(Config),
    HeaderBin = encode_header(Header, table_mod, ?TABLE_MOD_SIZE),
    << HeaderBin/binary, TableInt:8/integer, 0:24/integer, ConfigInt:32/integer >>;
encode2(#desc_stats_request{header = Header, flags = Flags}) ->
    TypeInt = ofp_map:stats_type(desc),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    HeaderBin = encode_header(Header, stats_request, ?DESC_STATS_REQUEST_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer >>;
encode2(#desc_stats_reply{header = Header, flags = Flags, mfr_desc = MFR,
                          hw_desc = HW, sw_desc = SW, serial_num = Serial,
                          dp_desc = DP}) ->
    TypeInt = ofp_map:stats_type(desc),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    MFRPad = (?DESC_STR_LEN - size(MFR)) * 8,
    HWPad = (?DESC_STR_LEN - size(HW)) * 8,
    SWPad = (?DESC_STR_LEN - size(SW)) * 8,
    SerialPad = (?SERIAL_NUM_LEN - size(Serial)) * 8,
    DPPad = (?DESC_STR_LEN - size(DP)) * 8,
    HeaderBin = encode_header(Header, stats_reply, ?DESC_STATS_REPLY_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       MFR/binary, 0:MFRPad/integer, HW/binary, 0:HWPad/integer,
       SW/binary, 0:SWPad/integer, Serial/binary, 0:SerialPad/integer,
       DP/binary, 0:DPPad/integer >>;
encode2(#flow_stats_request{header = Header, flags = Flags, table_id = Table,
                            out_port = Port, out_group = Group, cookie = Cookie,
                            cookie_mask = CookieMask, match = Match}) ->
    TypeInt = ofp_map:stats_type(flow),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    TableInt = ofp_map:encode_table_id(Table),
    PortInt = ofp_map:encode_port_number(Port),
    GroupInt = ofp_map:encode_group_id(Group),
    MatchBin = encode_struct(Match),
    Length = (?FLOW_STATS_REQUEST_SIZE - ?MATCH_SIZE) + size(MatchBin),
    HeaderBin = encode_header(Header, stats_request, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       TableInt:8/integer, 0:24/integer, PortInt:32/integer,
       GroupInt:32/integer, 0:32/integer, Cookie:8/binary, CookieMask:8/binary,
       MatchBin/binary >>;
encode2(#flow_stats_reply{header = Header, flags = Flags, stats = Stats}) ->
    TypeInt = ofp_map:stats_type(flow),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    StatsBin = encode_list(Stats),
    Length = ?FLOW_STATS_REPLY_SIZE + size(StatsBin),
    HeaderBin = encode_header(Header, stats_reply, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       StatsBin/binary >>;
encode2(#aggregate_stats_request{header = Header, flags = Flags,
                                 table_id = Table, out_port = Port,
                                 out_group = Group, cookie = Cookie,
                                 cookie_mask = CookieMask, match = Match}) ->
    TypeInt = ofp_map:stats_type(aggregate),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    TableInt = ofp_map:encode_table_id(Table),
    PortInt = ofp_map:encode_port_number(Port),
    GroupInt = ofp_map:encode_group_id(Group),
    MatchBin = encode_struct(Match),
    Length = ?AGGREGATE_STATS_REQUEST_SIZE + size(MatchBin),
    HeaderBin = encode_header(Header, stats_request, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       TableInt:8/integer, 0:24/integer, PortInt:32/integer,
       GroupInt:32/integer, 0:32/integer, Cookie:8/binary, CookieMask:8/binary,
       MatchBin/binary >>;
encode2(#aggregate_stats_reply{header = Header, flags = Flags,
                               packet_count = PCount, byte_count = BCount,
                               flow_count = FCount}) ->
    TypeInt = ofp_map:stats_type(aggregate),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    HeaderBin = encode_header(Header, stats_reply, ?AGGREGATE_STATS_REPLY_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       PCount:64/integer, BCount:64/integer, FCount:32/integer, 0:32/integer >>;
encode2(#table_stats_request{header = Header, flags = Flags}) ->
    TypeInt = ofp_map:stats_type(table),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    HeaderBin = encode_header(Header, stats_request, ?TABLE_STATS_REQUEST_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer >>;
encode2(#table_stats_reply{header = Header, flags = Flags, stats = Stats}) ->
    TypeInt = ofp_map:stats_type(table),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    StatsBin = encode_list(Stats),
    Length = ?TABLE_STATS_REPLY_SIZE + size(StatsBin),
    HeaderBin = encode_header(Header, stats_reply, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       StatsBin/binary >>;
encode2(#port_stats_request{header = Header, flags = Flags, port_no = Port}) ->
    TypeInt = ofp_map:stats_type(port),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    PortInt = ofp_map:encode_port_number(Port),
    HeaderBin = encode_header(Header, stats_request, ?PORT_STATS_REQUEST_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer,
       PortInt:32/integer, 0:32/integer >>;
encode2(#port_stats_reply{header = Header, flags = Flags, stats = Stats}) ->
    TypeInt = ofp_map:stats_type(port),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    StatsBin = encode_list(Stats),
    Length = ?TABLE_STATS_REPLY_SIZE + size(StatsBin),
    HeaderBin = encode_header(Header, stats_reply, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       StatsBin/binary >>;
encode2(#queue_stats_request{header = Header, flags = Flags,
                             port_no = Port, queue_id = Queue}) ->
    TypeInt = ofp_map:stats_type(queue),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    PortInt = ofp_map:encode_port_number(Port),
    QueueInt = ofp_map:encode_queue_id(Queue),
    HeaderBin = encode_header(Header, stats_request, ?QUEUE_STATS_REQUEST_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer,
       PortInt:32/integer, QueueInt:32/integer >>;
encode2(#queue_stats_reply{header = Header, flags = Flags, stats = Stats}) ->
    TypeInt = ofp_map:stats_type(queue),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    StatsBin = encode_list(Stats),
    Length = ?QUEUE_STATS_REPLY_SIZE + size(StatsBin),
    HeaderBin = encode_header(Header, stats_reply, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       StatsBin/binary >>;
encode2(#group_stats_request{header = Header, flags = Flags,
                             group_id = Group}) ->
    TypeInt = ofp_map:stats_type(group),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    GroupInt = ofp_map:encode_group_id(Group),
    HeaderBin = encode_header(Header, stats_request, ?GROUP_STATS_REQUEST_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer,
       GroupInt:32/integer, 0:32/integer >>;
encode2(#group_stats_reply{header = Header, flags = Flags, stats = Stats}) ->
    TypeInt = ofp_map:stats_type(group),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    StatsBin = encode_list(Stats),
    Length = ?GROUP_STATS_REPLY_SIZE + size(StatsBin),
    HeaderBin = encode_header(Header, stats_reply, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       StatsBin/binary >>;
encode2(#group_desc_stats_request{header = Header, flags = Flags}) ->
    TypeInt = ofp_map:stats_type(group_desc),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    HeaderBin = encode_header(Header, stats_request,
                              ?GROUP_DESC_STATS_REQUEST_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer >>;
encode2(#group_desc_stats_reply{header = Header, flags = Flags, stats = Stats}) ->
    TypeInt = ofp_map:stats_type(group_desc),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    StatsBin = encode_list(Stats),
    Length = ?GROUP_DESC_STATS_REPLY_SIZE + size(StatsBin),
    HeaderBin = encode_header(Header, stats_reply, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       StatsBin/binary >>;
encode2(#group_features_stats_request{header = Header, flags = Flags}) ->
    TypeInt = ofp_map:stats_type(group_features),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    HeaderBin = encode_header(Header, stats_request,
                              ?GROUP_FEATURES_STATS_REQUEST_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer >>;
encode2(#group_features_stats_reply{header = Header, flags = Flags,
                                    types = Types, capabilities = Capabilities,
                                    max_groups = {Max1, Max2, Max3, Max4},
                                    actions = {Actions1, Actions2,
                                               Actions3, Actions4}}) ->
    TypeInt = ofp_map:stats_type(group_features),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    TypesBin = flags_to_binary(group_type, Types, 4),
    CapabilitiesBin = flags_to_binary(group_capability, Capabilities, 4),
    Actions1Bin = flags_to_binary(action_type, Actions1, 4),
    Actions2Bin = flags_to_binary(action_type, Actions2, 4),
    Actions3Bin = flags_to_binary(action_type, Actions3, 4),
    Actions4Bin = flags_to_binary(action_type, Actions4, 4),
    HeaderBin = encode_header(Header, stats_reply,
                              ?GROUP_FEATURES_STATS_REPLY_SIZE),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin/binary, 0:32/integer,
       TypesBin/binary, CapabilitiesBin/binary,
       Max1:32/integer, Max2:32/integer, Max3:32/integer, Max4:32/integer,
       Actions1Bin/binary, Actions2Bin/binary, Actions3Bin/binary,
       Actions4Bin/binary >>;
encode2(#experimenter_stats_request{header = Header, flags = Flags,
                                    experimenter = Experimenter,
                                    exp_type = ExpType, data = Data}) ->
    TypeInt = ofp_map:stats_type(experimenter),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    Length = ?EXPERIMENTER_STATS_REQUEST_SIZE + byte_size(Data),
    HeaderBin = encode_header(Header, stats_request, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer,
       Experimenter:32/integer, ExpType:32/integer, Data/binary >>;
encode2(#experimenter_stats_reply{header = Header, flags = Flags,
                                  experimenter = Experimenter,
                                  exp_type = ExpType, data = Data}) ->
    TypeInt = ofp_map:stats_type(experimenter),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    Length = ?EXPERIMENTER_STATS_REPLY_SIZE + byte_size(Data),
    HeaderBin = encode_header(Header, stats_reply, Length),
    << HeaderBin/binary, TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer,
       Experimenter:32/integer, ExpType:32/integer, Data/binary >>;
encode2(#barrier_request{header = Header}) ->
    HeaderBin = encode_header(Header, barrier_request, ?BARRIER_REQUEST_SIZE),
    << HeaderBin/binary >>;
encode2(#barrier_reply{header = Header}) ->
    HeaderBin = encode_header(Header, barrier_reply, ?BARRIER_REPLY_SIZE),
    << HeaderBin/binary >>;
encode2(#role_request{header = Header, role = Role, generation_id = Gen}) ->
    RoleInt = ofp_map:controller_role(Role),
    HeaderBin = encode_header(Header, role_request, ?ROLE_REQUEST_SIZE),
    << HeaderBin/binary, RoleInt:32/integer, 0:32/integer, Gen:64/integer >>;
encode2(#role_reply{header = Header, role = Role, generation_id = Gen}) ->
    RoleInt = ofp_map:controller_role(Role),
    HeaderBin = encode_header(Header, role_reply, ?ROLE_REPLY_SIZE),
    << HeaderBin/binary, RoleInt:32/integer, 0:32/integer, Gen:64/integer >>;
encode2(Other) ->
    throw({bad_message, Other}).

%% @doc Decode header structure
-spec decode_header(binary()) -> ofp_header().
decode_header(Binary) ->
    << Experimental:1/integer, Version:7/integer, TypeInt:8/integer,
       Length:16/integer, XID:32/integer >> = Binary,
    case Length < 8 of
        true ->
            throw({error, bad_message});
        false ->
            Type = ofp_map:msg_type(TypeInt),
            {#ofp_header{experimental = Experimental == 1,
                         version = Version, xid = XID}, Type, Length}
    end.

%% @doc Decode port structure
decode_port(Binary) ->
    << PortNoInt:32/integer, 0:32/integer, HWAddr:6/binary, 0:16/integer,
       Name:16/binary, ConfigBin:4/binary, StateBin:4/binary,
       CurrBin:4/binary, AdvertisedBin:4/binary, SupportedBin:4/binary,
       PeerBin:4/binary, CurrSpeed:32/integer,
       MaxSpeed:32/integer >> = Binary,
    PortNo = ofp_map:decode_port_number(PortNoInt),
    Config = binary_to_flags(port_config, ConfigBin),
    State = binary_to_flags(port_state, StateBin),
    Curr = binary_to_flags(port_feature, CurrBin),
    Advertised = binary_to_flags(port_feature, AdvertisedBin),
    Supported = binary_to_flags(port_feature, SupportedBin),
    Peer = binary_to_flags(port_feature, PeerBin),
    Name2 = rstrip(Name),
    #port{port_no = PortNo, hw_addr = HWAddr, name = Name2, config = Config,
         state = State, curr = Curr, advertised = Advertised,
         supported = Supported, peer = Peer, curr_speed = CurrSpeed,
         max_speed = MaxSpeed}.

%% @doc Decode match structure
decode_match(Binary) ->
    PadFieldsLength = size(Binary) - ?MATCH_SIZE + 4,
    << TypeInt:16/integer, NoPadLength:16/integer,
       PadFieldsBin:PadFieldsLength/binary >> = Binary,
    FieldsBinLength = (NoPadLength - 4),
    Padding = (PadFieldsLength - FieldsBinLength) * 8,
    << FieldsBin:FieldsBinLength/binary, 0:Padding/integer >> = PadFieldsBin,
    Fields = decode_match_fields(FieldsBin),
    Type = ofp_map:match_type(TypeInt),
    #match{type = Type, oxm_fields = Fields}.

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
decode_match_field(<< Header:4/binary, Binary/binary >>) ->
    << ClassInt:16/integer, FieldInt:7/integer, HasMaskInt:1/integer,
       Length:8/integer >> = Header,
    Class = ofp_map:oxm_class(ClassInt),
    Field = ofp_map:oxm_field(Class, FieldInt),
    HasMask = (HasMaskInt =:= 1),
    case Class of
        openflow_basic ->
            BitLength = ofp_map:tlv_length(Field);
        _ ->
            BitLength = Length * 4
    end,
    case HasMask of
        false ->
            << Value:Length/binary, Rest/binary >> = Binary,
            TLV = #oxm_field{value = cut(Value, BitLength)};
        true ->
            Length2 = (Length div 2),
            << Value:Length2/binary, Mask:Length2/binary,
               Rest/binary >> = Binary,
            TLV = #oxm_field{value = cut(Value, BitLength),
                             mask = cut(Mask, BitLength)}
    end,
    {TLV#oxm_field{class = Class,
                   field = Field,
                   has_mask = HasMask}, Rest}.

%% @doc Decode actions
-spec decode_actions(binary()) -> [action()].
decode_actions(Binary) ->
    decode_actions(Binary, []).

-spec decode_actions(binary(), [action()]) -> [action()].
decode_actions(<<>>, Actions) ->
    lists:reverse(Actions);
decode_actions(Binary, Actions) ->
    << TypeInt:16/integer, Length:16/integer, Data/binary >> = Binary,
    Type = ofp_map:action_type(TypeInt),
    case Type of
        output ->
            << PortInt:32/integer, MaxLenInt:16/integer,
               0:48/integer, Rest/binary >> = Data,
            Port = ofp_map:decode_port_number(PortInt),
            MaxLen = ofp_map:decode_max_length(MaxLenInt),
            Action = #action_output{port = Port, max_len = MaxLen};
        group ->
            << GroupInt:32/integer, Rest/binary >> = Data,
            Group = ofp_map:decode_group_id(GroupInt),
            Action = #action_group{group_id = Group};
        set_queue ->
            << QueueInt:32/integer, Rest/binary >> = Data,
            Queue = ofp_map:decode_queue_id(QueueInt),
            Action = #action_set_queue{queue_id = Queue};
        set_mpls_ttl ->
            << TTL:8/integer, 0:24/integer, Rest/binary >> = Data,
            Action = #action_set_mpls_ttl{mpls_ttl = TTL};
        dec_mpls_ttl ->
            << 0:32/integer, Rest/binary >> = Data,
            Action = #action_dec_mpls_ttl{};
        set_nw_ttl ->
            << TTL:8/integer, 0:24/integer, Rest/binary >> = Data,
            Action = #action_set_nw_ttl{nw_ttl = TTL};
        dec_nw_ttl ->
            << 0:32/integer, Rest/binary >> = Data,
            Action = #action_dec_nw_ttl{};
        copy_ttl_out ->
            << 0:32/integer, Rest/binary >> = Data,
            Action = #action_copy_ttl_out{};
        copy_ttl_in ->
            << 0:32/integer, Rest/binary >> = Data,
            Action = #action_copy_ttl_in{};
        push_vlan ->
            << EtherType:16/integer, 0:16/integer, Rest/binary >> = Data,
            Action = #action_push_vlan{ethertype = EtherType};
        pop_vlan ->
            << 0:32/integer, Rest/binary >> = Data,
            Action = #action_pop_vlan{};
        push_mpls ->
            << EtherType:16/integer, 0:16/integer, Rest/binary >> = Data,
            Action = #action_push_mpls{ethertype = EtherType};
        pop_mpls ->
            << EtherType:16/integer, 0:16/integer, Rest/binary >> = Data,
            Action = #action_pop_mpls{ethertype = EtherType};
        set_field ->
            FieldLength = Length - 4,
            << FieldBin:FieldLength/binary, Rest/binary >> = Data,
            {Field, _Padding} = decode_match_field(FieldBin),
            Action = #action_set_field{field = Field};
        experimenter ->
            << Experimenter:32/integer, Rest/binary >> = Data,
            Action = #action_experimenter{experimenter = Experimenter}
        end,
    decode_actions(Rest, [Action | Actions]).

%% @doc Decode instructions
-spec decode_instructions(binary()) -> [instruction()].
decode_instructions(Binary) ->
    decode_instructions(Binary, []).

-spec decode_instructions(binary(), [instruction()]) -> [instruction()].
decode_instructions(<<>>, Instructions) ->
    lists:reverse(Instructions);
decode_instructions(Binary, Instructions) ->
    << TypeInt:16/integer, Length:16/integer, Data/binary >> = Binary,
    Type = ofp_map:instruction_type(TypeInt),
    case Type of
        goto_table ->
            << TableInt:8/integer, 0:24/integer, Rest/binary >> = Data,
            Table = ofp_map:decode_table_id(TableInt),
            Instruction = #instruction_goto_table{table_id = Table};
        write_metadata ->
            << 0:32/integer, Metadata:8/binary, MetaMask:8/binary,
               Rest/binary >> = Data,
            Instruction = #instruction_write_metadata{metadata = Metadata,
                                                      metadata_mask = MetaMask};
        write_actions ->
            ActionsLength = Length - ?INSTRUCTION_WRITE_ACTIONS_SIZE,
            << 0:32/integer, ActionsBin:ActionsLength/binary,
               Rest/binary >> = Data,
            Actions = decode_actions(ActionsBin),
            Instruction = #instruction_write_actions{actions = Actions};
        apply_actions ->
            ActionsLength = Length - ?INSTRUCTION_APPLY_ACTIONS_SIZE,
            << 0:32/integer, ActionsBin:ActionsLength/binary,
               Rest/binary >> = Data,
            Actions = decode_actions(ActionsBin),
            Instruction = #instruction_apply_actions{actions = Actions};
        clear_actions ->
            << 0:32/integer, Rest/binary >> = Data,
            Instruction = #instruction_clear_actions{};
        experimenter ->
            << Experimenter:32/integer, Rest/binary >> = Data,
            Instruction = #instruction_experimenter{experimenter = Experimenter}
    end,
    decode_instructions(Rest, [Instruction | Instructions]).

%% @doc Decode buckets
decode_buckets(Binary) ->
    decode_buckets(Binary, []).

decode_buckets(<<>>, Buckets) ->
    lists:reverse(Buckets);
decode_buckets(Binary, Buckets) ->
    << Length:16/integer, Weight:16/integer, Port:32/integer, Group:32/integer,
       0:32/integer, Data/binary >> = Binary,
    ActionsLength = Length - ?BUCKET_SIZE,
    << ActionsBin:ActionsLength/binary, Rest/binary >> = Data,
    Actions = decode_actions(ActionsBin),
    Bucket = #bucket{weight = Weight, watch_port = Port, watch_group = Group,
                     actions = Actions},
    decode_buckets(Rest, [Bucket | Buckets]).

%% @doc Decode queues
decode_queues(Binary) ->
    decode_queues(Binary, []).

decode_queues(<<>>, Queues) ->
    lists:reverse(Queues);
decode_queues(Binary, Queues) ->
    << QueueId:32/integer, Port:32/integer, Length:16/integer, 0:48/integer,
       Data/binary >> = Binary,
    PropsLength = Length - ?PACKET_QUEUE_SIZE,
    << PropsBin:PropsLength/binary, Rest/binary >> = Data,
    Props = decode_properties(PropsBin),
    Queue = #packet_queue{queue_id = QueueId, port = Port,
                          properties = Props},
    decode_queues(Rest, [Queue | Queues]).

%% @doc Decode properties
decode_properties(Binary) ->
    decode_properties(Binary, []).

decode_properties(<<>>, Properties) ->
    lists:reverse(Properties);
decode_properties(Binary, Properties) ->
    << TypeInt:16/integer, Length:16/integer, 0:32/integer,
       Data/binary >> = Binary,
    Type = ofp_map:queue_property(TypeInt),
    case Type of
        min_rate ->
            << Rate:16/integer, 0:48/integer, Rest/binary >> = Data,
            Property = #queue_prop_min_rate{rate = Rate};
        max_rate ->
            << Rate:16/integer, 0:48/integer, Rest/binary >> = Data,
            Property = #queue_prop_max_rate{rate = Rate};
        experimenter ->
            DataLength = Length - ?QUEUE_PROP_EXPERIMENTER_SIZE,
            << Experimenter:32/integer, 0:32/integer, ExpData:DataLength/binary,
               Rest/binary >> = Data,
            Property = #queue_prop_experimenter{experimenter = Experimenter,
                                                data = ExpData}
    end,
    decode_properties(Rest, [Property | Properties]).

decode_flow_stats(Binary) ->
    << _:16/integer, TableInt:8/integer, 0:8/integer, Sec:32/integer,
       NSec:32/integer, Priority:16/integer, Idle:16/integer, Hard:16/integer,
       0:48/integer, Cookie:8/binary, PCount:64/integer, BCount:64/integer,
       Data/binary >> = Binary,
    Table = ofp_map:decode_table_id(TableInt),
    << _:16/integer, MatchLength:16/integer, _/binary >> = Data,
    MatchLengthPad = MatchLength + (8 - (MatchLength rem 8)),
    << MatchBin:MatchLengthPad/binary, InstrsBin/binary >> = Data,
    Match = decode_match(MatchBin),
    Instrs = decode_instructions(InstrsBin),
    #flow_stats{table_id = Table, duration_sec = Sec, duration_nsec = NSec,
                priority = Priority, idle_timeout = Idle, hard_timeout = Hard,
                cookie = Cookie, packet_count = PCount, byte_count = BCount,
                match = Match, instructions = Instrs}.

decode_flow_stats_list(Binary) ->
    decode_flow_stats_list(Binary, []).

decode_flow_stats_list(<<>>, FlowStatsList) ->
    lists:reverse(FlowStatsList);
decode_flow_stats_list(Binary, FlowStatsList) ->
    << Length:16/integer, _/binary >> = Binary,
    << FlowStatsBin:Length/binary, Rest/binary >> = Binary,
    FlowStats = decode_flow_stats(FlowStatsBin),
    decode_flow_stats_list(Rest, [FlowStats | FlowStatsList]).

decode_table_stats(Binary) ->
    << TableInt:8/integer, 0:56/integer, NameBin:?OFP_MAX_TABLE_NAME_LEN/binary,
       MatchBin:8/binary, WildcardsBin:8/binary, WriteActionsBin:4/binary,
       ApplyActionsBin:4/binary, WriteSetBin:8/binary, ApplySetBin:8/binary,
       MetaMatch:64/integer, MetaWrite:64/integer, InstructionsBin:4/binary,
       ConfigInt:32/integer, Max:32/integer, ACount:32/integer, LCount:64/integer,
       MCount:64/integer >> = Binary,
    Table = ofp_map:decode_table_id(TableInt),
    Name = rstrip(NameBin),
    Match = binary_to_flags(oxm_field, MatchBin),
    Wildcards = binary_to_flags(oxm_field, WildcardsBin),
    WriteActions = binary_to_flags(action_type, WriteActionsBin),
    ApplyActions = binary_to_flags(action_type, ApplyActionsBin),
    WriteSet = binary_to_flags(oxm_field, WriteSetBin),
    ApplySet = binary_to_flags(oxm_field, ApplySetBin),
    Instructions = binary_to_flags(instruction_type, InstructionsBin),
    Config = ofp_map:table_config(ConfigInt),
    #table_stats{table_id = Table, name = Name, match = Match,
                           wildcards = Wildcards, write_actions = WriteActions,
                           apply_actions = ApplyActions,
                           write_setfields = WriteSet, apply_setfields = ApplySet,
                           metadata_match = MetaMatch, metadata_write = MetaWrite,
                           instructions = Instructions, config = Config,
                           max_entries = Max, active_count = ACount,
                           lookup_count = LCount, matched_count = MCount}.

decode_port_stats(Binary) ->
    << PortInt:32/integer, 0:32/integer, RXPackets:64/integer,
       TXPackets:64/integer, RXBytes:64/integer, TXBytes:64/integer,
       RXDropped:64/integer, TXDropped:64/integer, RXErrors:64/integer,
       TXErrors:64/integer, FrameErr:64/integer, OverErr:64/integer,
       CRCErr:64/integer, Collisions:64/integer >> = Binary,
    Port = ofp_map:decode_port_number(PortInt),
    #port_stats{port_no = Port,
                rx_packets = RXPackets, tx_packets = TXPackets,
                rx_bytes = RXBytes, tx_bytes = TXBytes,
                rx_dropped = RXDropped, tx_dropped = TXDropped,
                rx_errors = RXErrors, tx_errors = TXErrors,
                rx_frame_err = FrameErr, rx_over_err = OverErr,
                rx_crc_err = CRCErr, collisions = Collisions}.

decode_queue_stats(Binary) ->
    << PortInt:32/integer, QueueInt:32/integer, Bytes:64/integer,
       Packets:64/integer, Errors:64/integer >> = Binary,
    Port = ofp_map:decode_port_number(PortInt),
    Queue = ofp_map:decode_queue_id(QueueInt),
    #queue_stats{port_no = Port, queue_id = Queue, tx_bytes = Bytes,
                 tx_packets = Packets, tx_errors = Errors}.

decode_group_stats(Binary) ->
    << _:16/integer, 0:16/integer, GroupInt:32/integer, RefCount:32/integer,
       0:32/integer, PCount:64/integer, BCount:64/integer,
       BucketsBin/binary >> = Binary,
    Group = ofp_map:decode_group_id(GroupInt),
    Buckets = decode_bucket_counters(BucketsBin),
    #group_stats{group_id = Group, ref_count = RefCount, packet_count = PCount,
                 byte_count = BCount, bucket_stats = Buckets}.

decode_group_stats_list(Binary) ->
    decode_group_stats_list(Binary, []).

decode_group_stats_list(<<>>, StatsList) ->
    lists:reverse(StatsList);
decode_group_stats_list(Binary, StatsList) ->
    << Length:16/integer, _/binary >> = Binary,
    << StatsBin:Length/binary, Rest/binary >> = Binary,
    Stats = decode_group_stats(StatsBin),
    decode_group_stats_list(Rest, [Stats | StatsList]).

decode_bucket_counters(Binary) ->
    decode_bucket_counters(Binary, []).

decode_bucket_counters(<<>>, Buckets) ->
    lists:reverse(Buckets);
decode_bucket_counters(<< PCount:64/integer, BCount:64/integer, Rest/binary >>,
               Buckets) ->
    decode_bucket_counters(Rest,
                           [#bucket_counter{packet_count = PCount,
                                            byte_count = BCount} | Buckets]).

decode_group_desc_stats(Binary) ->
    << _:16/integer, TypeInt:8/integer, 0:8/integer,
       GroupInt:32/integer, BucketsBin/binary >> = Binary,
    Type = ofp_map:group_type(TypeInt),
    Group = ofp_map:decode_group_id(GroupInt),
    Buckets = decode_buckets(BucketsBin),
    #group_desc_stats{type = Type, group_id = Group,
                      buckets = Buckets}.

decode_group_desc_stats_list(Binary) ->
    decode_group_desc_stats_list(Binary, []).

decode_group_desc_stats_list(<<>>, StatsList) ->
    lists:reverse(StatsList);
decode_group_desc_stats_list(Binary, StatsList) ->
    << Length:16/integer, _/binary >> = Binary,
    << StatsBin:Length/binary, Rest/binary >> = Binary,
    Stats = decode_group_desc_stats(StatsBin),
    decode_group_desc_stats_list(Rest, [Stats | StatsList]).

%% @doc Actual decoding of the messages
-spec decode(atom(), integer(), ofp_header(), binary()) -> ofp_message().
decode(hello, _, Header, Rest) ->
    {#hello{header = Header}, Rest};
decode(error, Length, Header, Binary) ->
    << TypeInt:16/integer, More/binary >> = Binary,
    Type = ofp_map:error_type(TypeInt),
    case Type of
        experimenter ->
            DataLength = Length - ?ERROR_EXPERIMENTER_MSG_SIZE,
            << ExpTypeInt:16/integer, Experimenter:32/integer,
               Data:DataLength/binary, Rest/binary >> = More,
            {#error_experimenter_msg{header = Header, exp_type = ExpTypeInt,
                                     experimenter = Experimenter,
                                     data = Data}, Rest};
        _ ->
            DataLength = Length - ?ERROR_MSG_SIZE,
            << CodeInt:16/integer, Data:DataLength/binary, Rest/binary >> = More,
            Code = ofp_map:Type(CodeInt),
            {#error_msg{header = Header, type = Type,
                        code = Code, data = Data}, Rest}
    end;
decode(echo_request, Length, Header, Binary) ->
    DataLength = Length - ?ECHO_REQUEST_SIZE,
    << Data:DataLength/binary, Rest/binary >> = Binary,
    {#echo_request{header = Header, data = Data}, Rest};
decode(echo_reply, Length, Header, Binary) ->
    DataLength = Length - ?ECHO_REPLY_SIZE,
    << Data:DataLength/binary, Rest/binary >> = Binary,
    {#echo_reply{header = Header, data = Data}, Rest};
decode(experimenter, Length, Header, Binary) ->
    DataLength = Length - ?EXPERIMENTER_SIZE,
    << Experimenter:32/integer, Type:32/integer, Data:DataLength/binary,
       Rest/binary >> = Binary,
    {#experimenter{header = Header, experimenter = Experimenter,
                   exp_type = Type, data = Data}, Rest};
decode(features_request, _, Header, Rest) ->
    {#features_request{header = Header}, Rest};
decode(features_reply, Length, Header, Binary) ->
    PortsLength = Length - ?FEATURES_REPLY_SIZE,
    << DataPathMac:6/binary, DataPathID:16/integer, NBuffers:32/integer,
       NTables:8/integer, 0:24/integer, CapaBin:4/binary, 0:32/integer,
       PortsBin:PortsLength/binary, Rest/binary >> = Binary,
    Capabilities = binary_to_flags(capability, CapaBin),
    Ports = [decode_port(PortBin)
             || PortBin <- split_binaries(PortsBin, ?PORT_SIZE)],
    {#features_reply{header = Header, datapath_mac = DataPathMac,
                     datapath_id = DataPathID, n_buffers = NBuffers,
                     n_tables = NTables, capabilities = Capabilities,
                     ports = Ports}, Rest};
decode(get_config_request, _, Header, Rest) ->
    {#get_config_request{header = Header}, Rest};
decode(get_config_reply, _, Header, Binary) ->
    << FlagsBin:2/binary, Miss:16/integer, Rest/binary >> = Binary,
    Flags = binary_to_flags(configuration, FlagsBin),
    {#get_config_reply{header = Header, flags = Flags,
                       miss_send_len = Miss}, Rest};
decode(set_config, _, Header, Binary) ->
    << FlagsBin:2/binary, Miss:16/integer, Rest/binary >> = Binary,
    Flags = binary_to_flags(configuration, FlagsBin),
    {#set_config{header = Header, flags = Flags, miss_send_len = Miss}, Rest};
decode(packet_in, Length, Header, Binary) ->
    << BufferId:32/integer, TotalLen:16/integer, ReasonInt:8/integer,
       TableId:8/integer, Tail/binary >> = Binary,
    MatchLength = Length - (?PACKET_IN_SIZE - ?MATCH_SIZE) - 2 - TotalLen,
    << MatchBin:MatchLength/binary, 0:16, Payload/binary >> = Tail,
    Reason = ofp_map:reason(ReasonInt),
    Match = decode_match(MatchBin),
    << Data:TotalLen/binary, Rest/binary >> = Payload,
    {#packet_in{header = Header, buffer_id = BufferId, reason = Reason,
                table_id = TableId, match = Match, data = Data}, Rest};
decode(flow_removed, Length, Header, Binary) ->
    MatchLength = Length - ?FLOW_REMOVED_SIZE + ?MATCH_SIZE,
    << Cookie:8/binary, Priority:16/integer, ReasonInt:8/integer,
       TableId:8/integer, Sec:32/integer, NSec:32/integer, Idle:16/integer,
       Hard:16/integer, PCount:64/integer, BCount:64/integer,
       MatchBin:MatchLength/binary, Rest/binary >> = Binary,
    Reason = ofp_map:removed_reason(ReasonInt),
    Match = decode_match(MatchBin),
    {#flow_removed{header = Header, cookie = Cookie, priority = Priority,
                   reason = Reason, table_id = TableId, duration_sec = Sec,
                   duration_nsec = NSec, idle_timeout = Idle,
                   hard_timeout = Hard, packet_count = PCount,
                   byte_count = BCount, match = Match}, Rest};
decode(port_status, _, Header, Binary) ->
    << ReasonInt:8/integer, 0:56/integer, PortBin:?PORT_SIZE/binary,
       Rest/binary >> = Binary,
    Reason = ofp_map:port_reason(ReasonInt),
    Port = decode_port(PortBin),
    {#port_status{header = Header, reason = Reason, desc = Port}, Rest};
decode(stats_request, Length, Header, Binary) ->
    << TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer,
       Data/binary >> = Binary,
    Type = ofp_map:stats_type(TypeInt),
    Flags = binary_to_flags(stats_request_flag, FlagsBin),
    case Type of
        desc ->
            {#desc_stats_request{header = Header, flags = Flags}, Data};
        flow ->
            MatchLength = Length - (?FLOW_STATS_REQUEST_SIZE - ?MATCH_SIZE),
            << TableInt:8/integer, 0:24/integer, PortInt:32/integer,
               GroupInt:32/integer, 0:32/integer, Cookie:8/binary,
               CookieMask:8/binary, MatchBin:MatchLength/binary,
               Rest/binary >> = Data,
            Table = ofp_map:decode_table_id(TableInt),
            Port = ofp_map:decode_port_number(PortInt),
            Group = ofp_map:decode_group_id(GroupInt),
            Match = decode_match(MatchBin),
            {#flow_stats_request{header = Header, flags = Flags,
                                 table_id = Table, out_port = Port,
                                 out_group = Group, cookie = Cookie,
                                 cookie_mask = CookieMask, match = Match},
             Rest};
        aggregate ->
            MatchLength = Length - ?AGGREGATE_STATS_REQUEST_SIZE,
            << TableInt:8/integer, 0:24/integer, PortInt:32/integer,
               GroupInt:32/integer, 0:32/integer, Cookie:8/binary,
               CookieMask:8/binary, MatchBin:MatchLength/binary,
               Rest/binary >> = Data,
            Table = ofp_map:decode_table_id(TableInt),
            Port = ofp_map:decode_port_number(PortInt),
            Group = ofp_map:decode_group_id(GroupInt),
            Match = decode_match(MatchBin),
            {#aggregate_stats_request{header = Header, flags = Flags,
                                      table_id = Table, out_port = Port,
                                      out_group = Group, cookie = Cookie,
                                      cookie_mask = CookieMask, match = Match},
             Rest};
        table ->
            {#table_stats_request{header = Header, flags = Flags}, Data};
        port ->
            << PortInt:32/integer, 0:32/integer, Rest/binary >> = Data,
            Port = ofp_map:decode_port_number(PortInt),
            {#port_stats_request{header = Header, flags = Flags,
                                 port_no = Port}, Rest};
        queue ->
            << PortInt:32/integer, QueueInt:32/integer, Rest/binary >> = Data,
            Port = ofp_map:decode_port_number(PortInt),
            Queue = ofp_map:decode_queue_id(QueueInt),
            {#queue_stats_request{header = Header, flags = Flags,
                                  port_no = Port, queue_id = Queue}, Rest};
        group ->
            << GroupInt:32/integer, 0:32/integer, Rest/binary >> = Data,
            Group = ofp_map:decode_group_id(GroupInt),
            {#group_stats_request{header = Header, flags = Flags,
                                  group_id = Group}, Rest};
        group_desc ->
            {#group_desc_stats_request{header = Header, flags = Flags}, Data};
        group_features ->
            {#group_features_stats_request{header = Header,
                                           flags = Flags}, Data};
        experimenter ->
            DataLength = Length - ?EXPERIMENTER_STATS_REQUEST_SIZE,
            << Experimenter:32/integer, ExpType:32/integer,
               ExpData:DataLength/binary, Rest/binary >> = Data,
            {#experimenter_stats_request{header = Header, flags = Flags,
                                         experimenter = Experimenter,
                                         exp_type = ExpType, data = ExpData},
             Rest}
    end;
decode(stats_reply, Length, Header, Binary) ->
    << TypeInt:16/integer, FlagsBin:2/binary, 0:32/integer,
       Data/binary >> = Binary,
    Type = ofp_map:stats_type(TypeInt),
    Flags = binary_to_flags(stats_reply_flag, FlagsBin),
    case Type of
        desc ->
            << MFR:?DESC_STR_LEN/binary, HW:?DESC_STR_LEN/binary,
               SW:?DESC_STR_LEN/binary, Serial:?SERIAL_NUM_LEN/binary,
               DP:?DESC_STR_LEN/binary, Rest/binary >> = Data,
            {#desc_stats_reply{header = Header, flags = Flags,
                               mfr_desc = rstrip(MFR), hw_desc = rstrip(HW),
                               sw_desc = rstrip(SW),
                               serial_num = rstrip(Serial),
                               dp_desc = rstrip(DP)}, Rest};
        flow ->
            StatsLength = Length - ?FLOW_STATS_REPLY_SIZE,
            << StatsBin:StatsLength/binary, Rest/binary >> = Data,
            Stats = decode_flow_stats_list(StatsBin),
            {#flow_stats_reply{header = Header, flags = Flags,
                               stats = Stats}, Rest};
        aggregate ->
            << PCount:64/integer, BCount:64/integer, FCount:32/integer,
               0:32/integer, Rest/binary >> = Data,
            {#aggregate_stats_reply{header = Header, flags = Flags,
                                    packet_count = PCount, byte_count = BCount,
                                    flow_count = FCount}, Rest};
        table ->
            StatsLength = Length - ?TABLE_STATS_REPLY_SIZE,
            << StatsBin:StatsLength/binary, Rest/binary >> = Data,
            Stats = [decode_table_stats(TStats)
                     || TStats <- split_binaries(StatsBin, ?TABLE_STATS_SIZE)],
            {#table_stats_reply{header = Header, flags = Flags,
                                stats = Stats}, Rest};
        port ->
            StatsLength = Length - ?PORT_STATS_REPLY_SIZE,
            << StatsBin:StatsLength/binary, Rest/binary >> = Data,
            Stats = [decode_port_stats(PStats)
                     || PStats <- split_binaries(StatsBin, ?PORT_STATS_SIZE)],
            {#port_stats_reply{header = Header, flags = Flags,
                               stats = Stats}, Rest};
        queue ->
            StatsLength = Length - ?QUEUE_STATS_REPLY_SIZE,
            << StatsBin:StatsLength/binary, Rest/binary >> = Data,
            Stats = [decode_queue_stats(QStats)
                     || QStats <- split_binaries(StatsBin, ?QUEUE_STATS_SIZE)],
            {#queue_stats_reply{header = Header, flags = Flags,
                                stats = Stats}, Rest};
        group ->
            StatsLength = Length - ?GROUP_STATS_REPLY_SIZE,
            << StatsBin:StatsLength/binary, Rest/binary >> = Data,
            Stats = decode_group_stats_list(StatsBin),
            {#group_stats_reply{header = Header, flags = Flags,
                                stats = Stats}, Rest};
        group_desc ->
            StatsLength = Length - ?GROUP_DESC_STATS_REPLY_SIZE,
            << StatsBin:StatsLength/binary, Rest/binary >> = Data,
            Stats = decode_group_desc_stats_list(StatsBin),
            {#group_desc_stats_reply{header = Header, flags = Flags,
                                     stats = Stats}, Rest};
        group_features ->
            << TypesBin:4/binary, CapabilitiesBin:4/binary, Max1:32/integer,
               Max2:32/integer, Max3:32/integer, Max4:32/integer,
               Actions1Bin:4/binary, Actions2Bin:4/binary, Actions3Bin:4/binary,
               Actions4Bin:4/binary, Rest/binary >> = Data,
            Types = binary_to_flags(group_type, TypesBin),
            Capabilities = binary_to_flags(group_capability, CapabilitiesBin),
            Actions1 = binary_to_flags(action_type, Actions1Bin),
            Actions2 = binary_to_flags(action_type, Actions2Bin),
            Actions3 = binary_to_flags(action_type, Actions3Bin),
            Actions4 = binary_to_flags(action_type, Actions4Bin),
            {#group_features_stats_reply{header = Header, flags = Flags,
                                         types = Types,
                                         capabilities = Capabilities,
                                         max_groups = {Max1, Max2, Max3, Max4},
                                         actions = {Actions1, Actions2,
                                                    Actions3, Actions4}},
             Rest};
        experimenter ->
            DataLength = Length - ?EXPERIMENTER_STATS_REPLY_SIZE,
            << Experimenter:32/integer, ExpType:32/integer,
               ExpData:DataLength/binary, Rest/binary >> = Data,
            {#experimenter_stats_reply{header = Header, flags = Flags,
                                       experimenter = Experimenter,
                                       exp_type = ExpType, data = ExpData},
             Rest}
    end;
decode(queue_get_config_request, _, Header, Binary) ->
    << PortInt:32/integer, 0:32/integer, Rest/binary >> = Binary,
    Port = ofp_map:decode_port_number(PortInt),
    {#queue_get_config_request{header = Header, port = Port}, Rest};
decode(queue_get_config_reply, Length, Header, Binary) ->
    QueuesLength = Length - ?QUEUE_GET_CONFIG_REPLY_SIZE,
    << PortInt:32/integer, 0:32/integer, QueuesBin:QueuesLength/binary,
       Rest/binary >> = Binary,
    Port = ofp_map:decode_port_number(PortInt),
    Queues = decode_queues(QueuesBin),
    {#queue_get_config_reply{header = Header, port = Port,
                             queues = Queues}, Rest};
decode(packet_out, Length, Header, Binary) ->
    << BufferId:32/integer, PortInt:32/integer, ActionsLength:16/integer,
       0:48/integer, Binary2/binary >> = Binary,
    DataLength = Length - ?PACKET_OUT_SIZE - ActionsLength,
    << ActionsBin:ActionsLength/binary, Data:DataLength/binary,
       Rest/binary >> = Binary2,
    Port = ofp_map:decode_port_number(PortInt),
    Actions = decode_actions(ActionsBin),
    {#packet_out{header = Header, buffer_id = BufferId, in_port = Port,
                 actions = Actions, data = Data}, Rest};
decode(flow_mod, Length, Header, Binary) ->
    << Cookie:8/binary, CookieMask:8/binary, TableInt:8/integer,
       CommandInt:8/integer, Idle:16/integer, Hard:16/integer,
       Priority:16/integer, Buffer:32/integer, OutPortInt:32/integer,
       OutGroupInt:32/integer, FlagsBin:2/binary, 0:16/integer,
       Data/binary >> = Binary,
    Table = ofp_map:decode_table_id(TableInt),
    Command = ofp_map:flow_command(CommandInt),
    OutPort = ofp_map:decode_port_number(OutPortInt),
    OutGroup = ofp_map:decode_group_id(OutGroupInt),
    Flags = binary_to_flags(flow_flag, FlagsBin),
    << _:16/integer, MatchLength:16/integer, _/binary >> = Data,
    MatchLengthPad = MatchLength + (8 - (MatchLength rem 8)),
    InstrLength = Length - ?FLOW_MOD_SIZE + ?MATCH_SIZE - MatchLengthPad,
    << MatchBin:MatchLengthPad/binary, InstrBin:InstrLength/binary,
       Rest/binary >> = Data,
    Match = decode_match(MatchBin),
    Instructions = decode_instructions(InstrBin),
    {#flow_mod{header = Header, cookie = Cookie, cookie_mask = CookieMask,
               table_id = Table, command = Command, idle_timeout = Idle,
               hard_timeout = Hard, priority = Priority, buffer_id = Buffer,
               out_port = OutPort, out_group = OutGroup, flags = Flags,
               match = Match, instructions = Instructions}, Rest};
decode(group_mod, Length, Header, Binary) ->
    BucketsLength = Length - ?GROUP_MOD_SIZE,
    << CommandInt:16/integer, TypeInt:8/integer, 0:8/integer,
       GroupInt:32/integer, BucketsBin:BucketsLength/binary,
       Rest/binary >> = Binary,
    Command = ofp_map:group_command(CommandInt),
    Type = ofp_map:group_type(TypeInt),
    Group = ofp_map:decode_group_id(GroupInt),
    Buckets = decode_buckets(BucketsBin),
    {#group_mod{header = Header, command = Command, type = Type,
                group_id = Group, buckets = Buckets}, Rest};
decode(port_mod, _, Header, Binary) ->
    << PortInt:32/integer, 0:32/integer, Addr:6/binary,
       0:16/integer, ConfigBin:4/binary, MaskBin:4/binary,
       AdvertiseBin:4/binary, 0:32/integer, Rest/binary >> = Binary,
    Port = ofp_map:decode_port_number(PortInt),
    Config = binary_to_flags(port_config, ConfigBin),
    Mask = binary_to_flags(port_config, MaskBin),
    Advertise = binary_to_flags(port_feature, AdvertiseBin),
    {#port_mod{header = Header, port_no = Port, hw_addr = Addr,
               config = Config, mask = Mask, advertise = Advertise}, Rest};
decode(table_mod, _, Header, Binary) ->
    << TableInt:8/integer, 0:24/integer, ConfigInt:32/integer,
       Rest/binary >> = Binary,
    Table = ofp_map:decode_table_id(TableInt),
    Config = ofp_map:table_config(ConfigInt),
    {#table_mod{header = Header, table_id = Table, config = Config}, Rest};
decode(barrier_request, _, Header, Rest) ->
    {#barrier_request{header = Header}, Rest};
decode(barrier_reply, _, Header, Rest) ->
    {#barrier_reply{header = Header}, Rest};
decode(role_request, _, Header, Binary) ->
    << RoleInt:32/integer, 0:32/integer, Gen:64/integer, Rest/binary >> = Binary,
    Role = ofp_map:controller_role(RoleInt),
    {#role_request{header = Header, role = Role, generation_id = Gen}, Rest};
decode(role_reply, _, Header, Binary) ->
    << RoleInt:32/integer, 0:32/integer, Gen:64/integer, Rest/binary >> = Binary,
    Role = ofp_map:controller_role(RoleInt),
    {#role_reply{header = Header, role = Role, generation_id = Gen}, Rest}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

encode_list(List) ->
    encode_list(List, << >>).

encode_list([], Binaries) ->
    Binaries;
encode_list([Struct | Rest], Binaries) ->
    StructBin = encode_struct(Struct),
    encode_list(Rest, << Binaries/binary, StructBin/binary >>).

split_binaries(Binaries, Size) ->
    split_binaries(Binaries, [], Size).

split_binaries(<< >>, List, _) ->
    lists:reverse(List);
split_binaries(Binaries, List, Size) ->
    {Binary, Rest} = split_binary(Binaries, Size),
    split_binaries(Rest, [Binary | List], Size).

flags_to_binary(Type, Flags, Size) ->
    flags_to_binary(Type, Flags, << 0:(Size*8)/integer >>, Size*8).

flags_to_binary(_, [], Binary, _) ->
    Binary;
flags_to_binary(Type, [Flag | Rest], Binary, BitSize) ->
    << Binary2:BitSize/integer >> = Binary,
    case Flag of
        experimenter ->
            Bit = get_experimenter_bit(Type);
        _ ->
            Bit = ofp_map:Type(Flag)
    end,
    NewBinary = (Binary2 bor (1 bsl Bit)),
    flags_to_binary(Type, Rest, << NewBinary:BitSize/integer >>, BitSize).

binary_to_flags(Type, Binary) ->
    BitSize = size(Binary) * 8,
    << Integer:BitSize/integer >> = Binary,
    binary_to_flags(Type, Integer, BitSize-1, []).

binary_to_flags(Type, Integer, Bit, Flags) when Bit >= 0 ->
    case 0 /= (Integer band (1 bsl Bit)) of
        true ->
            Flag = ofp_map:Type(Bit),
            binary_to_flags(Type, Integer, Bit - 1, [Flag | Flags]);
        false ->
            binary_to_flags(Type, Integer, Bit - 1, Flags)
    end;
binary_to_flags(_, _, _, Flags) ->
    lists:reverse(Flags).

rstrip(Binary) ->
    rstrip(Binary, size(Binary) - 1).

rstrip(Binary, Byte) when Byte >= 0 ->
    case binary:at(Binary, Byte) of
        0 ->
            rstrip(Binary, Byte - 1);
        _ ->
            String = binary:part(Binary, 0, Byte + 1),
            << String/binary, 0:8/integer >>
    end;
rstrip(_, _) ->
    <<"\0">>.

cut(Binary, Bits) ->
    BitSize = size(Binary) * 8,
    case BitSize /= Bits of
        true ->
            << Int:BitSize/integer >> = Binary,
            NewInt = Int band round(math:pow(2,Bits) - 1),
            << NewInt:BitSize/integer >>;
        false ->
            Binary
    end.

get_experimenter_bit(instruction_type) ->
    ?OFPIT_EXPERIMENTER_BIT;
get_experimenter_bit(action_type) ->
    ?OFPAT_EXPERIMENTER_BIT.
