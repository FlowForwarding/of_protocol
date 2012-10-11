%%%-----------------------------------------------------------------------------
%%% Use is subject to License terms.
%%% @copyright (C) 2012 FlowForwarding.org
%%% @doc Common header file for all protocol versions.
%%% @end
%%%-----------------------------------------------------------------------------

-record(ofp_parser, {
          stack = <<>> :: binary()
         }).
-type ofp_parser() :: #ofp_parser{}.

-define(OFP_HEADER_SIZE, 8).

-record(ofp_message, {
          version = 3 :: integer(),
          xid :: integer(),
          body %% ofp_message_body()
         }).

-type ofp_message() :: #ofp_message{}.
