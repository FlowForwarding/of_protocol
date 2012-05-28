%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc Utility module with common functions.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_utils).
-author("Erlang Solutions Ltd. <openflow@erlang-solutions.com>").


-export([split_binaries/2,
         encode_string/2,
         strip_string/1,
         cut_bits/2,
         int_to_bool/1]).

%%%-----------------------------------------------------------------------------
%%% Helper functions
%%%-----------------------------------------------------------------------------

-spec split_binaries(binary(), integer()) -> [binary()].
split_binaries(Binaries, Size) ->
    split_binaries(Binaries, [], Size).

-spec split_binaries(binary(), [binary()], integer()) -> [binary()].
split_binaries(<<>>, List, _) ->
    lists:reverse(List);
split_binaries(Binaries, List, Size) ->
    {Binary, Rest} = split_binary(Binaries, Size),
    split_binaries(Rest, [Binary | List], Size).

-spec encode_string(binary(), integer()) -> binary().
encode_string(Binary, Length) when byte_size(Binary) >= Length - 1 ->
    Null = <<0:8>>,
    <<Binary:(Length - 1)/bytes, Null/bytes>>;
encode_string(Binary, Length) ->
    PaddingLength = (Length - byte_size(Binary)) * 8,
    Padding = <<0:PaddingLength>>,
    <<Binary/bytes, Padding/bytes>>.

-spec strip_string(binary()) -> binary().
strip_string(Binary) ->
    strip_string(Binary, size(Binary) - 1).

-spec strip_string(binary(), integer()) -> binary().
strip_string(Binary, Byte) when Byte >= 0 ->
    case binary:at(Binary, Byte) of
        0 ->
            strip_string(Binary, Byte - 1);
        _ ->
            String = binary:part(Binary, 0, Byte + 1),
            <<String/bytes, 0:8>>
    end;
strip_string(_, _) ->
    <<"\0">>.

-spec cut_bits(binary(), integer()) -> binary().
cut_bits(Binary, Bits) ->
    BitSize = bit_size(Binary),
    ByteSize = byte_size(Binary) * 8,
    <<Int:BitSize>> = Binary,
    NewInt = Int band round(math:pow(2,Bits) - 1),
    <<NewInt:ByteSize>>.

-spec int_to_bool(boolean()) -> integer().
int_to_bool(true) ->
    1;
int_to_bool(false) ->
    0.
