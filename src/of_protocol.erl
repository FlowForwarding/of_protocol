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

-define(VERSION, << 1:1/integer, 3:7/integer >>).
-define(XID, << 1:32/integer >>).

%%%-----------------------------------------------------------------------------
%%% API functions
%%%-----------------------------------------------------------------------------

%% @doc Encode erlang representation to binary.
-spec encode(record()) -> binary().
encode(Record) ->
    encode2(Record).

%% @doc Decode binary to erlang representation.
-spec decode(binary()) -> record().
decode(<< HeaderBin:8/binary, Rest/binary >>) ->
    Header = decode_header(HeaderBin),
    decode(Header#header.type, Header, Rest).

%%%-----------------------------------------------------------------------------
%%% Actual encode/decode functions
%%%-----------------------------------------------------------------------------

%% @doc Encode structures
encode_struct(#header{type = Type, length = Length}) ->
    TypeInt = ofp_map:type(Type),
    << ?VERSION/binary, TypeInt:8/integer, Length:16/integer, ?XID/binary >>;
encode_struct(#port{}) ->
    << 0:(?PORT_SIZE*8)/integer >>.

%% @doc Actual encoding of the messages
encode2(#hello{}) ->
    HeaderBin = encode_struct(#header{type = hello,
                                      length = ?HEADER_SIZE}),
    << HeaderBin/binary >>;
encode2(#error_msg{type = Type, code = Code, data = Data}) ->
    Length = size(Data) + ?ERROR_MSG_SIZE,
    HeaderBin = encode_struct(#header{type = error,
                                      length = Length}),
    TypeInt = ofp_map:error_type(Type),
    CodeInt = ofp_map:Type(Code),
    << HeaderBin/binary, TypeInt:16/integer, CodeInt:16/integer, Data/binary >>;
encode2(#echo_request{data = Data}) ->
    Length = size(Data) + ?ECHO_REQUEST_SIZE,
    HeaderBin = encode_struct(#header{type = echo_request,
                                      length = Length}),
    << HeaderBin/binary, Data/binary >>;
encode2(#echo_reply{data = Data}) ->
    Length = size(Data) + ?ECHO_REPLY_SIZE,
    HeaderBin = encode_struct(#header{type = echo_reply,
                                      length = Length}),
    << HeaderBin/binary, Data/binary >>;
encode2(#features_request{}) ->
    HeaderBin = encode_struct(#header{type = features_request,
                                      length = ?FEATURES_REQUEST_SIZE}),
    << HeaderBin/binary >>;
encode2(#features_reply{datapath_id = DataPathID, n_buffers = NBuffers,
                        n_tables = NTables, capabilities = Capabilities,
                        ports = Ports}) ->
    PortsBin = encode_list(Ports),
    Length = size(PortsBin) + ?FEATURES_REPLY_SIZE,
    HeaderBin = encode_struct(#header{type = features_reply,
                                      length = Length}),
    << HeaderBin/binary, DataPathID:8/binary, NBuffers:32/integer,
       NTables:8/integer, 0:24/integer, Capabilities:4/binary,
       0:32/integer, PortsBin/binary >>.

%% @doc Decode structures
decode_header(Binary) ->
    << _:1/integer, Version:7/integer, TypeInt:8/integer,
       Length:16/integer, XID:32/integer >> = Binary,
    Type = ofp_map:type(TypeInt),
    #header{version = Version, type = Type, length = Length, xid = XID}.
decode_port(_Binary) ->
    #port{}.

%% @doc Actual decoding of the messages
decode(hello, Header, _) ->
    #hello{header = Header};
decode(error, Header = #header{length = Length}, Binary) ->
    DataLength = Length - ?ERROR_MSG_SIZE,
    << TypeInt:16/integer, CodeInt:16/integer, Data:DataLength/binary >> = Binary,
    Type = ofp_map:error_type(TypeInt),
    Code = ofp_map:Type(CodeInt),
    #error_msg{header = Header, type = Type, code = Code, data = Data};
decode(echo_request, Header = #header{length = Length}, Binary) ->
    DataLength = Length - ?ECHO_REQUEST_SIZE,
    << Data:DataLength/binary >> = Binary,
    #echo_request{header = Header, data = Data};
decode(echo_reply, Header = #header{length = Length}, Binary) ->
    DataLength = Length - ?ECHO_REPLY_SIZE,
    << Data:DataLength/binary >> = Binary,
    #echo_reply{header = Header, data = Data};
decode(features_request, Header, _) ->
    #features_request{header = Header};
decode(features_reply, Header = #header{length = Length}, Binary) ->
    PortsLength = Length - ?FEATURES_REPLY_SIZE,
    << DataPathID:8/binary, NBuffers:32/integer, NTables:8/integer,
       0:24/integer, Capabilities:4/binary, 0:32/integer,
       PortsBin:PortsLength/binary >> = Binary,
    Ports = [decode_port(PortBin)
             || PortBin <- split_binaries(PortsBin, ?PORT_SIZE)],
    #features_reply{header = Header, datapath_id = DataPathID,
                    n_buffers = NBuffers, n_tables = NTables,
                    capabilities = Capabilities, ports = Ports}.

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
    flags_to_binary2(Type, Flags, << 0:(Size*8)/integer >>).

flags_to_binary2(_, [], Binary) ->
    Binary;
flags_to_binary2(Type, [Flag | Rest], Binary) ->
    Bit = ?MODULE:Type(Flag),
    NewBinary = (Binary bor (1 bsl Bit)),
    flags_to_binary2(Type, Rest, NewBinary).

binary_to_flags(Type, Binary) ->
    binary_to_flags(Type, Binary, size(Binary)*8-1, []).

binary_to_flags(_, _, -1, Flags) ->
    Flags;
binary_to_flags(Type, << Binary/integer >>, Bit, Flags) ->
    case 0 /= (Binary band (1 bsl Bit)) of
        true ->
            binary_to_flags(Type, Binary, Bit - 1, [ofp_map:Type(Bit) | Flags]);
        false ->
            binary_to_flags(Type, Binary, Bit - 1, Flags)
    end.
