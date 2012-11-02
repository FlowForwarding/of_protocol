%%%-----------------------------------------------------------------------------
%%% Use is subject to License terms.
%%% @copyright (C) 2012 FlowForwarding.org
%%% @doc Utility module with common functions.
%%% @end
%%%-----------------------------------------------------------------------------
-module(ofp_utils).
-author("Erlang Solutions Ltd. <openflow@erlang-solutions.com>").

-export([split_binaries/2,
         encode_string/2,
         strip_string/1,
         cut_bits/2,
         padding/2,
         binary_to_flags/3,
         flags_to_binary/4, 
         get_enum_name/3,
         get_enum_value/3,
         encode_list/3]).

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
    ByteSize = byte_size(Binary) * 8,
    BitSize = bit_size(Binary),
    <<Int:BitSize>> = Binary,
    TruncBin = <<Int:Bits>>,
    Padding = ByteSize - Bits,
    << 0:Padding, TruncBin/bits >>.

-spec padding(integer(), integer()) -> integer().
padding(Length, Padding) ->
    case Padding - (Length rem Padding) of
        Padding ->
            0;
        Else ->
            Else
    end.

-spec binary_to_flags(atom(), atom(), binary()) -> [atom()].
binary_to_flags(EnumMod, Type, Binary) ->
    BitSize = size(Binary) * 8,
    <<Integer:BitSize>> = Binary,
    binary_to_flags(EnumMod, Type, Integer, BitSize-1, []).

-spec flags_to_binary(atom(), atom(), [atom()], integer()) -> binary().
flags_to_binary(EnumMod, Type, Flags, Size) ->
    flags_to_binary(EnumMod, Type, Flags, <<0:(Size*8)>>, Size*8).

-spec get_enum_name(atom(), atom(), integer() | atom()) -> integer() | atom().
get_enum_name(EnumMod, Enum, Int) when is_integer(Int) ->
    %% TODO: Check if it's not larger than max
    try
        EnumMod:to_atom(Enum, Int)
    catch
        throw:bad_enum ->
            Int
    end;
get_enum_name(_, _, Atom) when is_atom(Atom)->
    Atom.

-spec get_enum_value(atom(), atom(), integer() | atom()) -> integer() | atom().
get_enum_value(EnumMod, Enum, Atom) when is_atom(Atom) ->
    %% TODO: Check if it's not larger than max
    try
        EnumMod:to_int(Enum, Atom)
    catch
        throw:bad_enum ->
            Atom
    end;
get_enum_value(_, _, Int) when is_integer(Int) ->
    Int.

-spec encode_list(function(), list(), binary()) -> binary().
encode_list(_Encoder, [], Binaries) ->
    Binaries;
encode_list(Encoder, [Struct | Rest], Binaries) ->
    StructBin = erlang:apply(Encoder, [Struct]),
    encode_list(Encoder, Rest, <<Binaries/bytes, StructBin/bytes>>).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-spec binary_to_flags(atom(), atom(), integer(), integer(), [atom()]) ->
                             [atom()].
binary_to_flags(EnumMod, Type, Integer, Bit, Flags) when Bit >= 0 ->
    case 0 /= (Integer band (1 bsl Bit)) of
        true ->
            Flag = experimenter_bit(EnumMod, Type, Bit),
            binary_to_flags(EnumMod, Type, Integer, Bit - 1, [Flag | Flags]);
        false ->
            binary_to_flags(EnumMod, Type, Integer, Bit - 1, Flags)
    end;
binary_to_flags(_, _, _, _, Flags) ->
    lists:reverse(Flags).

-spec flags_to_binary(atom(), atom(), [atom()], binary(), integer()) -> binary().
flags_to_binary(_, _, [], Binary, _) ->
    Binary;
flags_to_binary(EnumMod, Type, [Flag | Rest], Binary, BitSize) ->
    <<Binary2:BitSize>> = Binary,
    Bit = case Flag of
              experimenter ->
                  experimenter_bit(Type);
              Flag ->
                  EnumMod:to_int(Type, Flag)
          end,
    NewBinary = (Binary2 bor (1 bsl Bit)),
    flags_to_binary(EnumMod, Type, Rest, <<NewBinary:BitSize>>, BitSize).

%% TODO: Handle error if type is unexpected?
experimenter_bit(action_type) -> 31;
experimenter_bit(instruction_type) -> 31;
experimenter_bit(meter_band_type) -> 31.

experimenter_bit(_, action_type, 31) -> experimenter;
experimenter_bit(_, instruction_type, 31) -> experimenter;
experimenter_bit(_, meter_band_type, 31) -> experimenter;
experimenter_bit(EnumMod, Type, Bit) -> EnumMod:to_atom(Type, Bit).
