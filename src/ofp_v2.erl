%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc OpenFlow Protocol version 1.1 implementation.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_v2).

-behaviour(gen_protocol).

%% gen_protocol callbacks
-export([encode/1, decode/1]).

-include("of_protocol.hrl").
-include("ofp_v2.hrl").

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
                        peer = Peer, curr_speed = CurrSpeed,
                        max_speed = MaxSpeed}) ->
    PortNoInt = ofp_v2_map:encode_port_no(PortNo),
    NameBin = ofp_utils:encode_string(Name, ?OFP_MAX_PORT_NAME_LEN),
    ConfigBin = flags_to_binary(port_config, Config, 4),
    StateBin = flags_to_binary(port_state, State, 4),
    CurrBin = flags_to_binary(port_feature, Curr, 4),
    AdvertisedBin = flags_to_binary(port_feature, Advertised, 4),
    SupportedBin = flags_to_binary(port_feature, Supported, 4),
    PeerBin = flags_to_binary(port_feature, Peer, 4),
    <<PortNoInt:32, 0:32, HWAddr:?OFP_ETH_ALEN/bytes, 0:16,
      NameBin:?OFP_MAX_PORT_NAME_LEN/bytes,
      ConfigBin:4/bytes, StateBin:4/bytes, CurrBin:4/bytes,
      AdvertisedBin:4/bytes, SupportedBin:4/bytes,
      PeerBin:4/bytes, CurrSpeed:32, MaxSpeed:32>>.

%%% Messages -----------------------------------------------------------------

encode_body(_) ->
    <<>>.

%%%-----------------------------------------------------------------------------
%%% Decode functions
%%%-----------------------------------------------------------------------------

%% @doc Actual decoding of the message.
-spec do_decode(Binary :: binary()) -> ofp_message().
do_decode(Binary) ->
    <<ExperimentalInt:1, Version:7, TypeInt:8, _:16,
      XID:32, BodyBin/bytes >> = Binary,
    Experimental = (ExperimentalInt =:= 1),
    Type = ofp_v3_map:msg_type(TypeInt),
    Body = decode_body(Type, BodyBin),
    #ofp_message{experimental = Experimental, version = Version,
                 xid = XID, body = Body}.

%%% Structures -----------------------------------------------------------------

%% @doc Decode port structure.
decode_port(Binary) ->
    <<PortNoInt:32, 0:32, HWAddr:6/bytes, 0:16, NameBin:16/bytes,
      ConfigBin:4/bytes, StateBin:4/bytes, CurrBin:4/bytes,
      AdvertisedBin:4/bytes, SupportedBin:4/bytes, PeerBin:4/bytes,
      CurrSpeed:32, MaxSpeed:32>> = Binary,
    PortNo = ofp_v3_map:decode_port_no(PortNoInt),
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
              peer = Peer, curr_speed = CurrSpeed, max_speed = MaxSpeed}.

%%% Messages -----------------------------------------------------------------

decode_body(_, _) ->
    undefined.

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
    %%         Bit = ofp_v2_map:get_experimenter_bit(Type);
    %%     _ ->
            Bit = ofp_v2_map:Type(Flag),
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
            Flag = ofp_v2_map:Type(Bit),
            binary_to_flags(Type, Integer, Bit - 1, [Flag | Flags]);
        false ->
            binary_to_flags(Type, Integer, Bit - 1, Flags)
    end;
binary_to_flags(_, _, _, Flags) ->
    lists:reverse(Flags).

-spec type_int(ofp_message_body()) -> integer().
type_int(#ofp_hello{}) ->
    ofp_v3_map:msg_type(hello);
type_int(#ofp_error{}) ->
    ofp_v3_map:msg_type(error);
type_int(#ofp_error_experimenter{}) ->
    ofp_v3_map:msg_type(error);
type_int(#ofp_echo_request{}) ->
    ofp_v3_map:msg_type(echo_request);
type_int(#ofp_echo_reply{}) ->
    ofp_v3_map:msg_type(echo_reply);
type_int(#ofp_experimenter{}) ->
    ofp_v3_map:msg_type(experimenter);
type_int(#ofp_features_request{}) ->
    ofp_v3_map:msg_type(features_request);
type_int(#ofp_features_reply{}) ->
    ofp_v3_map:msg_type(features_reply);
type_int(#ofp_get_config_request{}) ->
    ofp_v3_map:msg_type(get_config_request);
type_int(#ofp_get_config_reply{}) ->
    ofp_v3_map:msg_type(get_config_reply);
type_int(#ofp_set_config{}) ->
    ofp_v3_map:msg_type(set_config);
type_int(#ofp_packet_in{}) ->
    ofp_v3_map:msg_type(packet_in);
type_int(#ofp_flow_removed{}) ->
    ofp_v3_map:msg_type(flow_removed);
type_int(#ofp_port_status{}) ->
    ofp_v3_map:msg_type(port_status);
type_int(#ofp_queue_get_config_request{}) ->
    ofp_v3_map:msg_type(queue_get_config_request);
type_int(#ofp_queue_get_config_reply{}) ->
    ofp_v3_map:msg_type(queue_get_config_reply);
type_int(#ofp_packet_out{}) ->
    ofp_v3_map:msg_type(packet_out);
type_int(#ofp_flow_mod{}) ->
    ofp_v3_map:msg_type(flow_mod);
type_int(#ofp_group_mod{}) ->
    ofp_v3_map:msg_type(group_mod);
type_int(#ofp_port_mod{}) ->
    ofp_v3_map:msg_type(port_mod);
type_int(#ofp_table_mod{}) ->
    ofp_v3_map:msg_type(table_mod);
type_int(#ofp_desc_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_desc_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_flow_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_flow_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_aggregate_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_aggregate_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_table_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_table_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_port_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_port_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_queue_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_queue_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_group_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_group_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_group_desc_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_group_desc_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_group_features_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_group_features_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_experimenter_stats_request{}) ->
    ofp_v3_map:msg_type(stats_request);
type_int(#ofp_experimenter_stats_reply{}) ->
    ofp_v3_map:msg_type(stats_reply);
type_int(#ofp_barrier_request{}) ->
    ofp_v3_map:msg_type(barrier_request);
type_int(#ofp_barrier_reply{}) ->
    ofp_v3_map:msg_type(barrier_reply).
