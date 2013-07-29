%%%-----------------------------------------------------------------------------
%%% Use is subject to License terms.
%%% @copyright (C) 2012 FlowForwarding.org
%%% @doc OpenFlow Protocol behaviour.
%%% @end
%%%-----------------------------------------------------------------------------
-module(gen_protocol).
-author("Erlang Solutions Ltd. <openflow@erlang-solutions.com>").

%% Encode OpenFlow Protocol message from Erlang representation to binary.
-callback encode(Message :: of_protocol:ofp_message()) ->
    {ok, Binary :: binary()} |
    {error, Reason :: any()}.

%% Decode OpenFlow Protocol message from binary to Erlang representation.
-callback decode(Binary :: binary()) ->
    {ok, Message :: of_protocol:ofp_message(), binary()} |
    {error, Reason :: any()}.
