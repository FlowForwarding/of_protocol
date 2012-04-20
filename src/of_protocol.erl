%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc OpenFlow Protocol library module.
%%% @end
%%%-----------------------------------------------------------------------------
-module(of_protocol).

%% API
-export([encode/1, decode/1, parse/2]).

-include("of_protocol.hrl").

-export_type([ofp_message/0, ofp_parser/0]).

%%%-----------------------------------------------------------------------------
%%% API functions
%%%-----------------------------------------------------------------------------

%% @doc Encode Erlang representation to binary.
-spec encode(ofp_message()) -> {ok, binary()} | {error, any()}.
encode(#ofp_message{version = Version} = Message) ->
    case get_module(Version) of
        undefined ->
            {error, unsupported_version};
        Module ->
            Module:encode(Message)
    end.

%% @doc Decode binary to Erlang representation.
-spec decode(binary()) -> {ok, ofp_message(), binary()} | {error, any()}.
decode(Binary) when byte_size(Binary) >= ?OFP_HEADER_SIZE ->
    <<_:1, Version:7, _:8, Length:16, _/bytes>> = Binary,
    case get_module(Version) of
        undefined ->
            {error, unsupported_version};
        Module ->
            case byte_size(Binary) >= Length of
                false ->
                    {error, binary_too_small};
                true ->
                    <<MessageBin:Length/bytes, Rest/bytes>> = Binary,
                    case Module:decode(MessageBin) of
                        {ok, Message} ->
                            {ok, Message, Rest};
                        {error, Reason} ->
                            {error, Reason}
                    end
            end
    end;
decode(_Binary) ->
    {error, binary_too_small}.

%% @doc Parse binary to messages in Erlang representation.
-spec parse(ofp_parser(), binary()) -> {ok, ofp_parser(), [ofp_message()]}.
parse(Parser, Binary) ->
    ofp_parser:parse(Parser, Binary).

%%%-----------------------------------------------------------------------------
%%% Helper functions
%%%-----------------------------------------------------------------------------

-spec get_module(integer()) -> atom().
get_module(3) ->
    ofp_v3;
%% get_module(2) ->
%%     ofp_v2;
get_module(1) ->
    ofp_v1;
get_module(_) ->
    undefined.
