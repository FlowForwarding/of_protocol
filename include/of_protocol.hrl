%%------------------------------------------------------------------------------
%% Copyright 2012 FlowForwarding.org
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%-----------------------------------------------------------------------------

%% @author Erlang Solutions Ltd. <openflow@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org
%% @doc Common header file for all protocol versions.

-define(OFP_HEADER_SIZE, 8).
-define(DEFAULT_VERSION, 3).

-define(MOD(Version), case Version of
                          3 -> ofp_v3;
                          4 -> ofp_v4;
                          _ -> unsupported
                      end).

%% Header ----------------------------------------------------------------------

-record(ofp_message, {
          version = ?DEFAULT_VERSION :: integer(),
          type :: atom(),
          xid = 0 :: integer(),
          body %% ofp_message_body()
         }).
-type ofp_message() :: #ofp_message{}.

%% Hello message ---------------------------------------------------------------

-type ofp_hello_element() :: {versionbitmap, [integer()]}.

-record(ofp_hello, {
          elements = [] :: [ofp_hello_element()]
         }).
-type ofp_hello() :: #ofp_hello{}.

%% Parser ----------------------------------------------------------------------

-record(ofp_parser, {
          version = ?DEFAULT_VERSION :: integer(),
          module :: atom(),
          stack = <<>> :: binary()
         }).
-type ofp_parser() :: #ofp_parser{}.
