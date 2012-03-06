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
          port_no :: integer(),
          hw_addr :: [integer()],
          name :: binary(),
          config = [] :: [atom()],
          state = [] :: [atom()],
          curr = [] :: [atom()],
          advertised = [] :: [atom()],
          supported = [] :: [atom()],
          peer = [] :: [atom()],
          curr_speed = 0 :: integer(),
          max_speed = 0 :: integer()
         }).

%% Flags to indicate behavior of the physical port
-define(OFPPC_PORT_DOWN, 0).
-define(OFPPC_NO_RECV, 2).
-define(OFPPC_NO_FWD, 5).
-define(OFPPC_NO_PACKET_IN, 6).

%% Current state of the physical port
-define(OFPPS_LINK_DOWN, 0).
-define(OFPPS_BLOCKED, 1).
-define(OFPPS_LIVE, 2).

%% Port numbering; Reserved ports
-define(OFPP_MAX, 16#ffffff00).
-define(OFPP_IN_PORT, 16#fffffff8).
-define(OFPP_TABLE, 16#fffffff9).
-define(OFPP_NORMAL, 16#fffffffa).
-define(OFPP_FLOOD, 16#fffffffb).
-define(OFPP_ALL, 16#fffffffc).
-define(OFPP_CONTROLLER, 16#fffffffd).
-define(OFPP_LOCAL, 16#fffffffe).
-define(OFPP_ANY, 16#ffffffff).

%% Features of ports available in a datapath
-define(OFPPF_10MB_HD, 0).
-define(OFPPF_10MB_FD, 1).
-define(OFPPF_100MB_HD, 2).
-define(OFPPF_100MB_FD, 3).
-define(OFPPF_1GB_HD, 4).
-define(OFPPF_1GB_FD, 5).
-define(OFPPF_10GB_FD, 6).
-define(OFPPF_40GB_FD, 7).
-define(OFPPF_100GB_FD, 8).
-define(OFPPF_1TB_FD, 9).
-define(OFPPF_OTHER, 10).
-define(OFPPF_COPPER, 11).
-define(OFPPF_FIBER, 12).
-define(OFPPF_AUTONEG, 13).
-define(OFPPF_PAUSE, 14).
-define(OFPPF_PAUSE_ASYM, 15).

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
