%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%%% @doc OpenFlow Protocol library module.
%%% @end
%%%-----------------------------------------------------------------------------
-module(of_protocol).

%% API
-export([encode/1, decode/1]).

-include("ofp_structures.hrl").
-include("ofp_messages.hrl").

-define(VERSION, << 1:1/integer, 3:7/integer >>).
-define(XID, << 1:32/integer >>).

%%%-----------------------------------------------------------------------------
%%% API functions
%%%-----------------------------------------------------------------------------

%% @doc Encode erlang representation to binary.
-spec encode(record()) -> binary().
encode(#header{type = Type, length = Length}) ->
    << ?VERSION/binary, Type:8/integer, Length:16/integer, ?XID/binary >>;
encode(#port{}) ->
    << 0:(?PORT_SIZE*8)/integer >>;
encode(#hello{}) ->
    HeaderBin = encode(#header{type = ?OFPT_HELLO,
                               length = ?HEADER_SIZE}),
    << HeaderBin/binary >>;
encode(#error_msg{type = Type, code = Code, data = Data}) ->
    Length = size(Data) + ?ERROR_MSG_SIZE,
    HeaderBin = encode(#header{type = ?OFPT_ERROR,
                               length = Length}),
    << HeaderBin/binary, Type:16/integer, Code:16/integer, Data/binary >>;
encode(#echo_request{data = Data}) ->
    Length = size(Data) + ?ECHO_REQUEST_SIZE,
    HeaderBin = encode(#header{type = ?OFPT_ECHO_REQUEST,
                               length = Length}),
    << HeaderBin/binary, Data/binary >>;
encode(#echo_reply{data = Data}) ->
    Length = size(Data) + ?ECHO_REPLY_SIZE,
    HeaderBin = encode(#header{type = ?OFPT_ECHO_REPLY,
                               length = Length}),
    << HeaderBin/binary, Data/binary >>;
encode(#features_request{}) ->
    HeaderBin = encode(#header{type = ?OFPT_FEATURES_REQUEST,
                               length = ?FEATURES_REQUEST_SIZE}),
    << HeaderBin/binary >>;
encode(#switch_features{datapath_id = DataPathID, n_buffers = NBuffers,
                        n_tables = NTables, capabilities = Capabilities,
                        ports = Ports}) ->
    PortsBin = encode_list(Ports),
    Length = size(PortsBin) + ?SWITCH_FEATURES_SIZE,
    HeaderBin = encode(#header{type = ?OFPT_FEATURES_REPLY,
                               length = Length}),
    << HeaderBin/binary, DataPathID:8/binary, NBuffers:32/integer,
       NTables:8/integer, 0:24/integer, Capabilities:4/binary,
       0:32/integer, PortsBin/binary >>.

%% @doc Decode binary to erlang representation.
-spec decode(binary()) -> record().
decode(<< HeaderBin:8/binary, Rest/binary >>) ->
    Header = decode_header(HeaderBin),
    decode(Header#header.type, Header, Rest).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

encode_list(List) ->
    encode_list(List, << >>).

encode_list([], Binaries) ->
    Binaries;
encode_list([Elem | Rest], Binaries) ->
    ElemBin = encode(Elem),
    encode_list(Rest, << Binaries/binary, ElemBin/binary >>).
    
split_binaries(Binaries, Size) ->
    split_binaries(Binaries, [], Size).

split_binaries(<< >>, List, _) ->
    lists:reverse(List);
split_binaries(Binaries, List, Size) ->
    {Binary, Rest} = split_binary(Binaries, Size),
    split_binaries(Rest, [Binary | List], Size).

decode_header(Binary) ->
    << _:1/integer, Version:7/integer, Type:8/integer,
       Length:16/integer, XID:32/integer >> = Binary,
    #header{version = Version, type = Type, length = Length, xid = XID}.

decode_port(_Binary) ->
    #port{}.

decode(?OFPT_HELLO, Header, _) ->
    #hello{header = Header};
decode(?OFPT_ERROR, Header = #header{length = Length}, Binary) ->
    DataLength = Length - ?ERROR_MSG_SIZE,
    << Type:16/integer, Code:16/integer, Data:DataLength/binary >> = Binary,
    #error_msg{header = Header, type = Type, code = Code, data = Data};
decode(?OFPT_ECHO_REQUEST, Header = #header{length = Length}, Binary) ->
    DataLength = Length - ?ECHO_REQUEST_SIZE,
    << Data:DataLength/binary >> = Binary,
    #echo_request{header = Header, data = Data};
decode(?OFPT_ECHO_REPLY, Header = #header{length = Length}, Binary) ->
    DataLength = Length - ?ECHO_REPLY_SIZE,
    << Data:DataLength/binary >> = Binary,
    #echo_reply{header = Header, data = Data};
decode(?OFPT_FEATURES_REQUEST, Header, _) ->
    #features_request{header = Header};
decode(?OFPT_FEATURES_REPLY, Header = #header{length = Length}, Binary) ->
    PortsLength = Length - ?SWITCH_FEATURES_SIZE,
    << DataPathID:8/binary, NBuffers:32/integer, NTables:8/integer,
       0:24/integer, Capabilities:4/binary, 0:32/integer,
       PortsBin:PortsLength/binary >> = Binary,
    Ports = [decode_port(PortBin)
             || PortBin <- split_binaries(PortsBin, ?PORT_SIZE)],
    #switch_features{header = Header, datapath_id = DataPathID,
                     n_buffers = NBuffers, n_tables = NTables,
                     capabilities = Capabilities, ports = Ports}.
