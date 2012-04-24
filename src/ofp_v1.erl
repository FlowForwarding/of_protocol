%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc OpenFlow Protocol version 1.0 implementation.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_v1).

-behaviour(gen_protocol).

%% gen_protocol callbacks
-export([encode/1, decode/1]).

-include("of_protocol.hrl").
-include("ofp_v1.hrl").

%%%-----------------------------------------------------------------------------
%%% gen_protocol callbacks
%%%-----------------------------------------------------------------------------

%% @doc Encode erlang representation to binary.
-spec encode(Message :: ofp_message()) -> {ok, binary()} |
                                          {error, any()}.
encode(Message) ->
    try
        {ok, do_encode(Message)}
    catch
        _:Exception ->
            {error, Exception}
    end.

%% @doc Decode binary to erlang representation.
-spec decode(Binary :: binary()) -> {ok, ofp_message()} |
                                    {error, any()}.
decode(Binary) ->
    try
        {ok, do_decode(Binary)}
    catch
        _:Exception ->
            {error, Exception}
    end.

%%%-----------------------------------------------------------------------------
%%% Encode functions
%%%-----------------------------------------------------------------------------

%% @doc Actual encoding of the message.
do_encode(#ofp_message{experimental = Experimental,
                       version = Version,
                       xid = Xid,
                       body = Body}) ->
    ExperimentalInt = ofp_utils:int_to_bool(Experimental),
    BodyBin = encode_body(Body),
    TypeInt = type_int(Body),
    Length = ?OFP_HEADER_SIZE + size(BodyBin),
    <<ExperimentalInt:1, Version:7, TypeInt:8,
      Length:16, Xid:32, BodyBin/bytes>>.

%%% Structures -----------------------------------------------------------------

%% @doc Encode other structures
encode_struct(#ofp_port{port_no = PortNo, hw_addr = HWAddr, name = Name,
                        config = Config, state = State, curr = Curr,
                        advertised = Advertised, supported = Supported,
                        peer = Peer}) ->
    PortNoInt = ofp_v1_map:encode_port_no(PortNo),
    NameBin = ofp_utils:encode_string(Name, ?OFP_MAX_PORT_NAME_LEN),
    ConfigBin = flags_to_binary(port_config, Config, 4),
    StateBin = flags_to_binary(port_state, State, 4),
    CurrBin = flags_to_binary(port_feature, Curr, 4),
    AdvertisedBin = flags_to_binary(port_feature, Advertised, 4),
    SupportedBin = flags_to_binary(port_feature, Supported, 4),
    PeerBin = flags_to_binary(port_feature, Peer, 4),
    <<PortNoInt:16, HWAddr:?OFP_ETH_ALEN/bytes,
      NameBin:?OFP_MAX_PORT_NAME_LEN/bytes,
      ConfigBin:4/bytes, StateBin:4/bytes, CurrBin:4/bytes,
      AdvertisedBin:4/bytes, SupportedBin:4/bytes, PeerBin:4/bytes>>;

encode_struct(#ofp_packet_queue{queue_id = Queue, properties = Props}) ->
    PropsBin = encode_list(Props),
    Length = ?PACKET_QUEUE_SIZE + size(PropsBin),
    <<Queue:32, Length:16, 0:16, PropsBin/bytes>>;
encode_struct(#ofp_queue_prop_min_rate{rate = Rate}) ->
    PropertyInt = ofp_v1_map:queue_property(min_rate),
    <<PropertyInt:16, ?QUEUE_PROP_MIN_RATE_SIZE:16, 0:32, Rate:16, 0:48>>;

encode_struct(#ofp_match{oxm_fields = Fields}) ->
    FieldList = encode_fields(Fields),
    InPort = encode_field_value(FieldList, in_port, 16),
    EthSrc = encode_field_value(FieldList, eth_src, 48),
    EthDst = encode_field_value(FieldList, eth_dst, 48),
    VlanVid = encode_field_value(FieldList, vlan_vid, 16),
    VlanPcp = encode_field_value(FieldList, vlan_pcp, 8),
    EthType = encode_field_value(FieldList, eth_type, 16),
    IPDscp = encode_field_value(FieldList, ip_dscp, 8),
    IPProto = encode_field_value(FieldList, ip_proto, 8),
    IPv4Src = encode_field_value(FieldList, ipv4_src, 32),
    IPv4Dst = encode_field_value(FieldList, ipv4_dst, 32),
    case IPProto of
        <<6>> ->
            TPSrc = encode_field_value(FieldList, tcp_src, 16),
            TPDst = encode_field_value(FieldList, tcp_dst, 16);
        <<17>> ->
            TPSrc = encode_field_value(FieldList, udp_src, 16),
            TPDst = encode_field_value(FieldList, udp_dst, 16);
        _ ->
            TPSrc = <<0:16>>,
            TPDst = <<0:16>>
    end,
    SrcMask = case lists:keyfind(ipv4_src, #ofp_field.field, Fields) of
                  #ofp_field{has_mask = true, mask = SMask} ->
                      count_zeros4(SMask);
                  _ ->
                      0
              end,
    DstMask = case lists:keyfind(ipv4_dst, #ofp_field.field, Fields) of
                  #ofp_field{has_mask = true, mask = DMask} ->
                      count_zeros4(DMask);
                  _ ->
                      0
              end,
    {Wildcards, _} = lists:unzip(FieldList),
    <<WildcardsInt:32>> = flags_to_binary(flow_wildcard,
                                          Wildcards -- [ipv4_src, ipv4_dst], 4),
    WildcardsBin = <<((bnot WildcardsInt) bor (SrcMask bsl 8)
                          bor (DstMask bsl 14)):32>>,
    <<WildcardsBin:4/bytes, InPort:2/bytes, EthSrc:6/bytes, EthDst:6/bytes,
      VlanVid:2/bytes, VlanPcp:1/bytes, 0:8, EthType:2/bytes, IPDscp:1/bytes,
      IPProto:1/bytes, 0:16, IPv4Src:4/bytes, IPv4Dst:4/bytes, TPSrc:2/bytes,
      TPDst:2/bytes>>;

encode_struct(#ofp_action_output{port = Port, max_len = MaxLen}) ->
    Type = ofp_v1_map:action_type(output),
    Length = ?ACTION_OUTPUT_SIZE,
    PortInt = ofp_v1_map:encode_port_no(Port),
    MaxLenInt = ofp_v1_map:encode_buffer_id(MaxLen),
    <<Type:16, Length:16, PortInt:16, MaxLenInt:16>>;
encode_struct(#ofp_action_set_queue{port = Port, queue_id = Queue}) ->
    Type = ofp_v1_map:action_type(set_queue),
    QueueInt = ofp_v1_map:encode_queue_id(Queue),
    Length = ?ACTION_SET_QUEUE_SIZE,
    <<Type:16, Length:16, Port:16, 0:48, QueueInt:32>>;
encode_struct(#ofp_action_pop_vlan{}) ->
    Type = ofp_v1_map:action_type(pop_vlan),
    Length = ?ACTION_POP_VLAN_SIZE,
    <<Type:16, Length:16, 0:32>>;
encode_struct(#ofp_action_experimenter{experimenter = Experimenter}) ->
    Type = ofp_v1_map:action_type(experimenter),
    Length = ?ACTION_EXPERIMENTER_SIZE,
    <<Type:16, Length:16, Experimenter:32>>;

encode_struct(#ofp_action_set_field{field = #ofp_field{field = Type,
                                                       value = Value}}) ->
    SetType = ofp_v1_map:action_set_type(Type),
    case Type of
        vlan_vid ->
            <<SetType:16, ?ACTION_SET_VLAN_VID_SIZE:16, Value:16/bits, 0:16>>;
        vlan_pcp ->
            <<SetType:16, ?ACTION_SET_VLAN_PCP_SIZE:16, Value:8/bits, 0:24>>;
        eth_src ->
            <<SetType:16, ?ACTION_SET_ETH_SIZE:16, Value:48/bits, 0:48>>;
        eth_dst ->
            <<SetType:16, ?ACTION_SET_ETH_SIZE:16, Value:48/bits, 0:48>>;
        ipv4_src ->
            <<SetType:16, ?ACTION_SET_IPV4_SIZE:16, Value:32/bits>>;
        ipv4_dst ->
            <<SetType:16, ?ACTION_SET_IPV4_SIZE:16, Value:32/bits>>;
        ip_dscp ->
            <<SetType:16, ?ACTION_SET_IP_DSCP_SIZE:16, Value:8/bits, 0:24>>;
        tcp_src ->
            <<SetType:16, ?ACTION_SET_TP_SIZE:16, Value:16/bits, 0:16>>;
        tcp_dst ->
            <<SetType:16, ?ACTION_SET_TP_SIZE:16, Value:16/bits, 0:16>>;
        udp_src ->
            <<SetType:16, ?ACTION_SET_TP_SIZE:16, Value:16/bits, 0:16>>;
        udp_dst ->
            <<SetType:16, ?ACTION_SET_TP_SIZE:16, Value:16/bits, 0:16>>;
        sctp_src ->
            <<SetType:16, ?ACTION_SET_TP_SIZE:16, Value:16/bits, 0:16>>;
        sctp_dst ->
            <<SetType:16, ?ACTION_SET_TP_SIZE:16, Value:16/bits, 0:16>>
    end.

%% FIXME: Add a separate case when encoding port_no
encode_field_value(FieldList, Type, Size) ->
    case lists:keyfind(Type, 1, FieldList) of
        false ->
            <<0:Size>>;
        {_, Value} ->
            <<Value:Size/bits>>
    end.

encode_fields(Fields) ->
    encode_fields(Fields, []).

encode_fields([], FieldList) ->
    FieldList;
encode_fields([#ofp_field{field = Type, value = Value} | Rest], FieldList) ->
    encode_fields(Rest, [{Type, Value} | FieldList]).

encode_actions(Actions) ->
    encode_actions(Actions, <<>>).

encode_actions([], Actions) ->
    Actions;
encode_actions([Action | Rest], Actions) ->
    ActionBin = encode_struct(Action),
    encode_actions(Rest, <<Actions/bytes, ActionBin/bytes>>).

%%% Messages -------------------------------------------------------------------

-spec encode_body(ofp_message()) -> binary().
encode_body(#ofp_hello{}) ->
    <<>>;
encode_body(#ofp_echo_request{data = Data}) ->
    Data;
encode_body(#ofp_echo_reply{data = Data}) ->
    Data;
encode_body(#ofp_features_request{}) ->
    <<>>;
encode_body(#ofp_features_reply{datapath_mac = DataPathMac,
                                datapath_id = DataPathID, n_buffers = NBuffers,
                                n_tables = NTables, capabilities = Capabilities,
                                actions = _Actions, ports = Ports}) ->
    PortsBin = encode_list(Ports),
    CapaBin = flags_to_binary(capability, Capabilities, 4),
    %% FIXME: Encode actions
    ActionsBin = <<0:32>>,
    <<DataPathMac:6/bytes, DataPathID:16, NBuffers:32, NTables:8,
      0:24, CapaBin:4/bytes, ActionsBin:4/bytes, PortsBin/bytes>>;
encode_body(#ofp_desc_stats_request{flags = Flags}) ->
    TypeInt = ofp_v1_map:stats_type(desc),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes>>;
encode_body(#ofp_desc_stats_reply{flags = Flags, mfr_desc = MFR,
                                  hw_desc = HW, sw_desc = SW,
                                  serial_num = Serial, dp_desc = DP}) ->
    TypeInt = ofp_v1_map:stats_type(desc),
    FlagsBin = flags_to_binary(stats_reply_flag, Flags, 2),
    MFRPad = (?DESC_STR_LEN - size(MFR)) * 8,
    HWPad = (?DESC_STR_LEN - size(HW)) * 8,
    SWPad = (?DESC_STR_LEN - size(SW)) * 8,
    SerialPad = (?SERIAL_NUM_LEN - size(Serial)) * 8,
    DPPad = (?DESC_STR_LEN - size(DP)) * 8,
    <<TypeInt:16, FlagsBin/bytes,
      MFR/bytes, 0:MFRPad, HW/bytes, 0:HWPad,
      SW/bytes, 0:SWPad, Serial/bytes, 0:SerialPad,
      DP/bytes, 0:DPPad>>;
encode_body(#ofp_flow_stats_request{flags = Flags, table_id = Table,
                                    out_port = Port, match = Match}) ->
    TypeInt = ofp_v1_map:stats_type(flow),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    TableInt = ofp_v1_map:encode_table_id(Table),
    PortInt = ofp_v1_map:encode_port_no(Port),
    MatchBin = encode_struct(Match),
    <<TypeInt:16, FlagsBin:2/bytes, MatchBin:?MATCH_SIZE/bytes,
      TableInt:8, 0:8, PortInt:16>>;
encode_body(#ofp_table_stats_request{flags = Flags}) ->
    TypeInt = ofp_v1_map:stats_type(table),
    FlagsBin = flags_to_binary(stats_request_flag, Flags, 2),
    <<TypeInt:16, FlagsBin:2/bytes>>;
encode_body(#ofp_get_config_request{}) ->
    <<>>;
encode_body(#ofp_get_config_reply{flags = Flags, miss_send_len = Miss}) ->
    FlagsBin = flags_to_binary(configuration, Flags, 2),
    <<FlagsBin:2/bytes, Miss:16>>;
encode_body(#ofp_set_config{flags = Flags, miss_send_len = Miss}) ->
    FlagsBin = flags_to_binary(configuration, Flags, 2),
    <<FlagsBin:2/bytes, Miss:16>>;
encode_body(#ofp_flow_mod{match = Match, cookie = Cookie, command = Command,
                          idle_timeout = Idle, hard_timeout = Hard,
                          priority = Priority, buffer_id = Buffer,
                          out_port = OutPort,  flags = Flags,
                          instructions = Instructions}) ->
    BufferInt = ofp_v1_map:encode_buffer_id(Buffer),
    CommandInt = ofp_v1_map:flow_command(Command),
    OutPortInt = ofp_v1_map:encode_port_no(OutPort),
    FlagsBin = flags_to_binary(flow_flag, Flags, 2),
    MatchBin = encode_struct(Match),
    GetActions = fun(#ofp_instruction_write_actions{actions = Actions}, []) ->
                         Actions;
                    (#ofp_instruction_write_actions{}, Actions) ->
                         Actions;
                    (_, Actions) ->
                         Actions
                 end,
    Actions = lists:foldl(GetActions, [], Instructions),
    ActionsBin = encode_actions(Actions),
    <<MatchBin/bytes, Cookie:8/bytes, CommandInt:16, Idle:16, Hard:16,
      Priority:16, BufferInt:32, OutPortInt:16, FlagsBin:2/bytes,
      ActionsBin/bytes>>.

%%%-----------------------------------------------------------------------------
%%% Decode functions
%%%-----------------------------------------------------------------------------

%% @doc Actual decoding of the message.
-spec do_decode(Binary :: binary()) -> ofp_message().
do_decode(Binary) ->
    <<ExperimentalInt:1, Version:7, TypeInt:8, _:16,
      XID:32, BodyBin/bytes >> = Binary,
    Experimental = (ExperimentalInt =:= 1),
    Type = ofp_v1_map:msg_type(TypeInt),
    Body = decode_body(Type, BodyBin),
    #ofp_message{experimental = Experimental, version = Version,
                 xid = XID, body = Body}.

%%% Structures -----------------------------------------------------------------

%% @doc Decode port structure.
decode_port(Binary) ->
    <<PortNoInt:16, HWAddr:6/bytes, NameBin:?OFP_MAX_PORT_NAME_LEN/bytes,
      ConfigBin:4/bytes, StateBin:4/bytes, CurrBin:4/bytes,
      AdvertisedBin:4/bytes, SupportedBin:4/bytes, PeerBin:4/bytes>> = Binary,
    PortNo = ofp_v1_map:decode_port_no(PortNoInt),
    Name = ofp_utils:strip_string(NameBin),
    Config = binary_to_flags(port_config, ConfigBin),
    State = binary_to_flags(port_state, StateBin),
    Curr = binary_to_flags(port_feature, CurrBin),
    Advertised = binary_to_flags(port_feature, AdvertisedBin),
    Supported = binary_to_flags(port_feature, SupportedBin),
    Peer = binary_to_flags(port_feature, PeerBin),
    #ofp_port{port_no = PortNo, hw_addr = HWAddr, name = Name,
              config = Config, state = State, curr = Curr,
              advertised = Advertised, supported = Supported,
              peer = Peer}.

%% @doc Decode packet queues
decode_packet_queues(Binary) ->
    decode_packet_queues(Binary, []).

decode_packet_queues(<<>>, Queues) ->
    lists:reverse(Queues);
decode_packet_queues(Binary, Queues) ->
    <<QueueId:32, Length:16, 0:16, Data/bytes>> = Binary,
    PropsLength = Length - ?PACKET_QUEUE_SIZE,
    <<PropsBin:PropsLength/bytes, Rest/bytes>> = Data,
    Props = decode_queue_properties(PropsBin),
    Queue = #ofp_packet_queue{queue_id = QueueId, properties = Props},
    decode_packet_queues(Rest, [Queue | Queues]).

%% @doc Decode queue properties
decode_queue_properties(Binary) ->
    decode_queue_properties(Binary, []).

decode_queue_properties(<<>>, Properties) ->
    lists:reverse(Properties);
decode_queue_properties(Binary, Properties) ->
    <<TypeInt:16, _Length:16, 0:32, Data/bytes>> = Binary,
    Type = ofp_v1_map:queue_property(TypeInt),
    case Type of
        min_rate ->
            <<Rate:16, 0:48, Rest/bytes>> = Data,
            Property = #ofp_queue_prop_min_rate{rate = Rate}
    end,
    decode_queue_properties(Rest, [Property | Properties]).

decode_match(Binary) ->
    <<WildcardsInt:32, InPort:2/bytes, EthSrc:6/bytes, EthDst:6/bytes,
      VlanVid:2/bytes, VlanPcp:1/bytes, 0:8, EthType:2/bytes, IPDscp:1/bytes,
      IPProto:1/bytes, 0:16, IPv4Src:4/bytes, IPv4Dst:4/bytes,
      TPSrc:2/bytes, TPDst:2/bytes>> = Binary,
    Wildcards = binary_to_flags(flow_wildcard,
                                <<((bnot WildcardsInt) band 16#30003f):32>>),
    case lists:member(ip_proto, Wildcards) of
        false ->
            Wildcards2 = Wildcards;
        true ->
            <<TPDstBit:1, TPSrcBit:1, _:6>> = <<WildcardsInt:8>>,
            case TPSrcBit of
                0 ->
                    WildcardsTmp = Wildcards;
                1 ->
                    AddTmp = case IPProto of
                                 <<6>> -> [tcp_src];
                                 <<17>> -> [udp_src];
                                 _ -> []
                             end,
                    WildcardsTmp = Wildcards ++ AddTmp
            end,
            case TPDstBit of
                0 ->
                    Wildcards2 = WildcardsTmp;
                1 ->
                    Add2 = case IPProto of
                               <<6>> -> [tcp_dst];
                               <<17>> -> [udp_dst];
                               _ -> []
                           end,
                    Wildcards2 = WildcardsTmp ++ Add2
            end
    end,
    Fields = [begin
                  F = #ofp_field{class = openflow_basic, field = Type},
                  case Type of
                      in_port ->
                          F#ofp_field{value = InPort};
                      eth_src ->
                          F#ofp_field{value = EthSrc};
                      eth_dst ->
                          F#ofp_field{value = EthDst};
                      vlan_vid ->
                          F#ofp_field{value = VlanVid};
                      vlan_pcp ->
                          F#ofp_field{value = VlanPcp};
                      eth_type ->
                          F#ofp_field{value = EthType};
                      ip_dscp ->
                          F#ofp_field{value = IPDscp};
                      ip_proto ->
                          F#ofp_field{value = IPProto};
                      ipv4_src ->
                          <<_:18, SrcMask:6, _:8>> = <<WildcardsInt:32>>,
                          F#ofp_field{value = IPv4Src,
                                      has_mask = true,
                                      mask = convert_to_mask(SrcMask)};
                      ipv4_dst ->
                          <<_:12, DstMask:6, _:14>> = <<WildcardsInt:32>>,
                          F#ofp_field{value = IPv4Dst,
                                      has_mask = true,
                                      mask = convert_to_mask(DstMask)};
                      tcp_src ->
                          F#ofp_field{value = TPSrc};
                      tcp_dst ->
                          F#ofp_field{value = TPDst};
                      udp_src ->
                          F#ofp_field{value = TPSrc};
                      udp_dst ->
                          F#ofp_field{value = TPDst}
                  end
              end || Type <- Wildcards2 ++ [ipv4_src, ipv4_dst]],
    #ofp_match{type = standard, oxm_fields = Fields}.

%% @doc Decode actions
-spec decode_actions(binary()) -> [ofp_action()].
decode_actions(Binary) ->
    decode_actions(Binary, []).

-spec decode_actions(binary(), [ofp_action()]) -> [ofp_action()].
decode_actions(<<>>, Actions) ->
    lists:reverse(Actions);
decode_actions(Binary, Actions) ->
    <<TypeInt:16, _Length:16, Data/bytes>> = Binary,
    Type = ofp_v1_map:action_type(TypeInt),
    case Type of
        output ->
            <<PortInt:16, MaxLenInt:16, Rest/bytes>> = Data,
            Port = ofp_v1_map:decode_port_no(PortInt),
            MaxLen = ofp_v1_map:decode_buffer_id(MaxLenInt),
            Action = [#ofp_action_output{port = Port, max_len = MaxLen}];
        set_queue ->
            <<Port:16, _:48, QueueInt:32, Rest/bytes>> = Data,
            Action = [#ofp_action_set_queue{port = Port, queue_id = QueueInt}];
        pop_vlan ->
            <<_:32, Rest/bytes>> = Data,
            Action = [#ofp_action_pop_vlan{}];
        experimenter ->
            <<Experimenter:32, Rest/bytes>> = Data,
            Action = [#ofp_action_experimenter{experimenter = Experimenter}];
        set_field ->
            case SetType = ofp_v1_map:action_set_type(TypeInt) of
                tp_src ->
                    <<Value:16, _:16, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = tcp_src,
                                                    value = Value}}
                              %% #ofp_action_set_field{
                              %%    field = #ofp_field{class = openflow_basic,
                              %%                       field = udp_src,
                              %%                       value = Value}}
                             ];
                tp_dst ->
                    <<Value:16, _:16, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = tcp_dst,
                                                    value = Value}}
                              %% #ofp_action_set_field{
                              %%    field = #ofp_field{class = openflow_basic,
                              %%                       field = udp_dst,
                              %%                       value = Value}}
                             ];
                vlan_pcp ->
                    <<Value:8, _:24, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = SetType,
                                                    value = Value}}];
                ip_dscp ->
                    <<Value:8, _:24, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = SetType,
                                                    value = Value}}];
                vlan_vid ->
                    <<Value:16, _:16, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = SetType,
                                                    value = Value}}];
                ipv4_src ->
                    <<Value:32, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = SetType,
                                                    value = Value}}];
                ipv4_dst ->
                    <<Value:32, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = SetType,
                                                    value = Value}}];
                eth_src ->
                    <<Value:48, _:48, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = SetType,
                                                    value = Value}}];
                eth_dst ->
                    <<Value:48, _:48, Rest/bytes>> = Data,
                    Action = [#ofp_action_set_field{
                                 field = #ofp_field{class = openflow_basic,
                                                    field = SetType,
                                                    value = Value}}]
            end
    end,
    decode_actions(Rest, Action ++ Actions).

%%% Messages -----------------------------------------------------------------

-spec decode_body(atom(), binary()) -> ofp_message().
decode_body(hello, _) ->
    #ofp_hello{};
decode_body(features_request, _) ->
    #ofp_features_request{};
decode_body(echo_request, Data) ->
    #ofp_echo_request{data = Data};
decode_body(echo_reply, Data) ->
    #ofp_echo_reply{data = Data};
decode_body(features_reply, Binary) ->
    PortsLength = size(Binary) - ?FEATURES_REPLY_SIZE + ?OFP_HEADER_SIZE,
    <<DataPathMac:6/bytes, DataPathID:16, NBuffers:32,
      NTables:8, 0:24, CapaBin:4/bytes, _ActionsBin:4/bytes,
      PortsBin:PortsLength/bytes>> = Binary,
    Capabilities = binary_to_flags(capability, CapaBin),
    %% FIXME: Decode actions
    Actions = [],
    Ports = [decode_port(PortBin)
             || PortBin <- ofp_utils:split_binaries(PortsBin, ?PORT_SIZE)],
    #ofp_features_reply{datapath_mac = DataPathMac,
                        datapath_id = DataPathID, n_buffers = NBuffers,
                        n_tables = NTables, capabilities = Capabilities,
                        actions = Actions, ports = Ports};
decode_body(get_config_request, _) ->
    #ofp_get_config_request{};
decode_body(get_config_reply, Binary) ->
    <<FlagsBin:2/bytes, Miss:16>> = Binary,
    Flags = binary_to_flags(configuration, FlagsBin),
    #ofp_get_config_reply{flags = Flags,
                          miss_send_len = Miss};
decode_body(set_config, Binary) ->
    <<FlagsBin:2/bytes, Miss:16>> = Binary,
    Flags = binary_to_flags(configuration, FlagsBin),
    #ofp_set_config{flags = Flags, miss_send_len = Miss};
decode_body(flow_mod, Binary) ->
    <<MatchBin:40/bytes, Cookie:8/bytes, CommandInt:16, Idle:16, Hard:16,
      Priority:16, BufferInt:32, OutPortInt:16, FlagsBin:2/bytes,
      ActionsBin/bytes>> = Binary,
    Buffer = ofp_v1_map:decode_buffer_id(BufferInt),
    Command = ofp_v1_map:flow_command(CommandInt),
    OutPort = ofp_v1_map:decode_port_no(OutPortInt),
    Flags = binary_to_flags(flow_flag, FlagsBin),
    Match = decode_match(MatchBin),
    Actions = decode_actions(ActionsBin),
    Instructions = case Actions of
                       [] ->
                           [];
                       _ ->
                           [#ofp_instruction_write_actions{actions = Actions}]
                   end,
    #ofp_flow_mod{cookie = Cookie, cookie_mask = <<0:64>>, table_id = 0,
                  command = Command, idle_timeout = Idle, hard_timeout = Hard,
                  priority = Priority, buffer_id = Buffer, out_port = OutPort,
                  out_group = 16#fffffffe, flags = Flags, match = Match,
                  instructions = Instructions};
decode_body(stats_request, Binary) ->
    <<TypeInt:16, FlagsBin:2/bytes, Data/bytes>> = Binary,
    Type = ofp_v1_map:stats_type(TypeInt),
    Flags = binary_to_flags(stats_request_flag, FlagsBin),
    case Type of
        desc ->
            #ofp_desc_stats_request{flags = Flags};
        flow ->
            <<MatchBin:?MATCH_SIZE/bytes, TableInt:8, _:8, PortInt:16>> = Data,
            Table = ofp_v1_map:decode_table_id(TableInt),
            Port = ofp_v1_map:decode_port_no(PortInt),
            Match = decode_match(MatchBin),
            #ofp_flow_stats_request{flags = Flags, table_id = Table,
                                    out_port = Port, out_group = 16#fffffffe,
                                    cookie = <<0:64>>, cookie_mask = <<0:64>>,
                                    match = Match};
        table ->
            #ofp_table_stats_request{flags = Flags}
    end.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-spec encode_list(list()) -> binary().
encode_list(List) ->
    encode_list(List, <<>>).

-spec encode_list(list(), binary()) -> binary().
encode_list([], Binaries) ->
    Binaries;
encode_list([Struct | Rest], Binaries) ->
    StructBin = encode_struct(Struct),
    encode_list(Rest, <<Binaries/bytes, StructBin/bytes>>).

-spec flags_to_binary(atom(), [atom()], integer()) -> binary().
flags_to_binary(Type, Flags, Size) ->
    flags_to_binary(Type, Flags, <<0:(Size*8)>>, Size*8).

-spec flags_to_binary(atom(), [atom()], binary(), integer()) -> binary().
flags_to_binary(_, [], Binary, _) ->
    Binary;
flags_to_binary(Type, [Flag | Rest], Binary, BitSize) ->
    <<Binary2:BitSize>> = Binary,
    %% case Flag of
    %%     experimenter ->
    %%         Bit = ofp_v1_map:get_experimenter_bit(Type);
    %%     _ ->
            Bit = ofp_v1_map:Type(Flag),
    %% end,
    NewBinary = (Binary2 bor (1 bsl Bit)),
    flags_to_binary(Type, Rest, <<NewBinary:BitSize>>, BitSize).

-spec binary_to_flags(atom(), binary()) -> [atom()].
binary_to_flags(Type, Binary) ->
    BitSize = size(Binary) * 8,
    <<Integer:BitSize>> = Binary,
    binary_to_flags(Type, Integer, BitSize-1, []).

-spec binary_to_flags(atom(), integer(), integer(), [atom()]) -> [atom()].
binary_to_flags(Type, Integer, Bit, Flags) when Bit >= 0 ->
    case 0 /= (Integer band (1 bsl Bit)) of
        true ->
            Flag = ofp_v1_map:Type(Bit),
            binary_to_flags(Type, Integer, Bit - 1, [Flag | Flags]);
        false ->
            binary_to_flags(Type, Integer, Bit - 1, Flags)
    end;
binary_to_flags(_, _, _, Flags) ->
    lists:reverse(Flags).

-spec convert_to_mask(integer()) -> binary().
convert_to_mask(N) when N < 32 ->
    <<(16#ffffffff - ((1 bsl N) -1)):32>>;
convert_to_mask(_) ->
    <<(16#0):32>>.

-spec count_zeros4(binary()) -> integer().
count_zeros4(<<X,0,0,0>>) -> 24 + count_zeros1(X);
count_zeros4(<<_,X,0,0>>) -> 16 + count_zeros1(X);
count_zeros4(<<_,_,X,0>>) -> 8 + count_zeros1(X);
count_zeros4(<<_,_,_,X>>) -> count_zeros1(X).

-spec count_zeros1(binary()) -> integer().
count_zeros1(X) when X band 2#11111111 == 0 -> 8;
count_zeros1(X) when X band 2#01111111 == 0 -> 7;
count_zeros1(X) when X band 2#00111111 == 0 -> 6;
count_zeros1(X) when X band 2#00011111 == 0 -> 5;
count_zeros1(X) when X band 2#00001111 == 0 -> 4;
count_zeros1(X) when X band 2#00000111 == 0 -> 3;
count_zeros1(X) when X band 2#00000011 == 0 -> 2;
count_zeros1(X) when X band 2#00000001 == 0 -> 1;
count_zeros1(_) -> 0.

-spec type_int(ofp_message_body()) -> integer().
type_int(#ofp_hello{}) ->
    ofp_v1_map:msg_type(hello);
type_int(#ofp_error{}) ->
    ofp_v1_map:msg_type(error);
type_int(#ofp_error_experimenter{}) ->
    ofp_v1_map:msg_type(error);
type_int(#ofp_echo_request{}) ->
    ofp_v1_map:msg_type(echo_request);
type_int(#ofp_echo_reply{}) ->
    ofp_v1_map:msg_type(echo_reply);
type_int(#ofp_experimenter{}) ->
    ofp_v1_map:msg_type(experimenter);
type_int(#ofp_features_request{}) ->
    ofp_v1_map:msg_type(features_request);
type_int(#ofp_features_reply{}) ->
    ofp_v1_map:msg_type(features_reply);
type_int(#ofp_get_config_request{}) ->
    ofp_v1_map:msg_type(get_config_request);
type_int(#ofp_get_config_reply{}) ->
    ofp_v1_map:msg_type(get_config_reply);
type_int(#ofp_set_config{}) ->
    ofp_v1_map:msg_type(set_config);
type_int(#ofp_packet_in{}) ->
    ofp_v1_map:msg_type(packet_in);
type_int(#ofp_flow_removed{}) ->
    ofp_v1_map:msg_type(flow_removed);
type_int(#ofp_port_status{}) ->
    ofp_v1_map:msg_type(port_status);
type_int(#ofp_queue_get_config_request{}) ->
    ofp_v1_map:msg_type(queue_get_config_request);
type_int(#ofp_queue_get_config_reply{}) ->
    ofp_v1_map:msg_type(queue_get_config_reply);
type_int(#ofp_packet_out{}) ->
    ofp_v1_map:msg_type(packet_out);
type_int(#ofp_flow_mod{}) ->
    ofp_v1_map:msg_type(flow_mod);
type_int(#ofp_port_mod{}) ->
    ofp_v1_map:msg_type(port_mod);
type_int(#ofp_desc_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_desc_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_flow_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_flow_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_aggregate_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_aggregate_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_table_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_table_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_port_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_port_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_queue_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_queue_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_group_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_group_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_group_desc_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_group_desc_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_group_features_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_group_features_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_experimenter_stats_request{}) ->
    ofp_v1_map:msg_type(stats_request);
type_int(#ofp_experimenter_stats_reply{}) ->
    ofp_v1_map:msg_type(stats_reply);
type_int(#ofp_barrier_request{}) ->
    ofp_v1_map:msg_type(barrier_request);
type_int(#ofp_barrier_reply{}) ->
    ofp_v1_map:msg_type(barrier_reply).
