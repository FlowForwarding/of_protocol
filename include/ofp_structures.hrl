%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%%%-----------------------------------------------------------------------------

%%%-----------------------------------------------------------------------------
%%% Common Structures
%%%-----------------------------------------------------------------------------

%% Header on all OpenFlow packets
-define(HEADER_SIZE, 8).
-record(header, {
          version = 3 :: integer(),
          type :: atom(),
          length :: integer(),
          xid :: integer()
         }).

-define(OFPT_HELLO, 0).
-define(OFPT_ERROR, 1).
-define(OFPT_ECHO_REQUEST, 2).
-define(OFPT_ECHO_REPLY, 3).
-define(OFPT_EXPERIMENTER, 4).
-define(OFPT_FEATURES_REQUEST, 5).
-define(OFPT_FEATURES_REPLY, 6).
-define(OFPT_GET_CONFIG_REQUEST, 7).
-define(OFPT_GET_CONFIG_REPLY, 8).
-define(OFPT_SET_CONFIG, 9).

%%% Port Structures ------------------------------------------------------------

%% Description of a port
-define(PORT_SIZE, 64).
-record(port, {
          no :: integer(),
          hw_addr,
          name :: binary(),
          config,
          state,
          curr,
          advertised,
          supported,
          peer,
          curr_speed,
          max_speed
         }).

%%% Queue Structures -----------------------------------------------------------

%% Common description for a queue
-record(queue_prop_header, {
          type :: integer(),
          length :: integer()
         }).

%% Full description for a queue
-record(packet_queue, {
          id :: integer(),
          port,
          length :: integer(),
          properties :: #queue_prop_header{}
         }).

%% Min-Rate queue property description
-record(queue_prop_min_rate, {
          header :: #queue_prop_header{},
          rate :: integer()
         }).

%% Max-Rate queue property description
-record(queue_prop_max_rate, {
          header :: #queue_prop_header{},
          rate :: integer()
         }).

%% Experimenter queue property description
%% -record(queue_prop_experimenter, {
%%           header :: #queue_prop_header{},
%%           experimenter :: #experimenter_header{},
%%           data :: binary()
%%          }).

%%% Flow Match Structures ------------------------------------------------------

%% Fields to match against flows
-record(match, {
          type :: integer(),
          length :: integer(),
          oxm_fields
         }).

%%% Flow Instruction Structures ------------------------------------------------



%%% Action Structures ----------------------------------------------------------

%% Action header that is common to all actions
-record(action_header, {
          type :: integer(),
          length :: integer()
         }).

-record(action_output, {
          type,
          length :: integer(),
          port,
          max_len
         }).

-record(action_group, {
          type,
          length :: integer(),
          group_id
         }).

-record(action_set_queue, {
          type,
          length :: integer(),
          queue_id
         }).

-record(action_mpls_ttl, {
          type,
          length :: integer(),
          mpls_ttl
         }).

-record(action_nw_ttl, {
          type,
          length :: integer(),
          nw_ttl
         }).

-record(action_push, {
          type,
          length :: integer(),
          ethertype
         }).

-record(action_pop_mpls, {
          type,
          length :: integer(),
          ethertype
         }).

%% -record(action_experimenter_header, {
%%           type,
%%           length :: integer(),
%%           experimenter :: #experimenter_header{}
%%          }).
