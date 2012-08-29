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
%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org

-define(VERSION, 3).

%% Maximum values --------------------------------------------------------------

-define(OFPP_MAX, 16#ffffff00). %% port number
-define(OFPQ_MAX, 16#fffffffe). %% queue id
-define(OFPG_MAX, 16#fffffffd). %% group id
-define(OFPTT_MAX, 16#fe).      %% table id
-define(OFPCML_MAX, 16#ffe5).   %% buffer id

%% Message sizes (in bytes) ----------------------------------------------------

-define(FEATURES_REQUEST_SIZE, 8).
-define(FEATURES_REPLY_SIZE, 32).
-define(GET_CONFIG_REQUEST_SIZE, 8).
-define(GET_CONFIG_REPLY_SIZE, 12).
-define(SET_CONFIG_SIZE, 12).
-define(TABLE_MOD_SIZE, 16).
-define(FLOW_MOD_SIZE, 56).
-define(GROUP_MOD_SIZE, 16).
-define(PORT_MOD_SIZE, 40).
-define(DESC_STATS_REQUEST_SIZE, 16).
-define(DESC_STATS_REPLY_SIZE, 1072).
-define(FLOW_STATS_REQUEST_SIZE, 56).
-define(FLOW_STATS_REPLY_SIZE, 16).
-define(AGGREGATE_STATS_REQUEST_SIZE, 56).
-define(AGGREGATE_STATS_REPLY_SIZE, 40).
-define(TABLE_STATS_REQUEST_SIZE, 16).
-define(TABLE_STATS_REPLY_SIZE, 16).
-define(PORT_STATS_REQUEST_SIZE, 24).
-define(PORT_STATS_REPLY_SIZE, 16).
-define(QUEUE_STATS_REQUEST_SIZE, 24).
-define(QUEUE_STATS_REPLY_SIZE, 16).
-define(GROUP_STATS_REQUEST_SIZE, 24).
-define(GROUP_STATS_REPLY_SIZE, 16).
-define(GROUP_DESC_STATS_REQUEST_SIZE, 16).
-define(GROUP_DESC_STATS_REPLY_SIZE, 16).
-define(GROUP_FEATURES_STATS_REQUEST_SIZE, 16).
-define(GROUP_FEATURES_STATS_REPLY_SIZE, 56).
-define(EXPERIMENTER_STATS_REQUEST_SIZE, 24).
-define(EXPERIMENTER_STATS_REPLY_SIZE, 24).
-define(QUEUE_GET_CONFIG_REQUEST_SIZE, 16).
-define(QUEUE_GET_CONFIG_REPLY_SIZE, 16).
-define(PACKET_OUT_SIZE, 24).
-define(BARRIER_REQUEST_SIZE, 8).
-define(BARRIER_REPLY_SIZE, 8).
-define(ROLE_REQUEST_SIZE, 24).
-define(ROLE_REPLY_SIZE, 24).
-define(PACKET_IN_SIZE, 24).
-define(FLOW_REMOVED_SIZE, 56).
-define(PORT_STATUS_SIZE, 80).
-define(ERROR_SIZE, 12).
-define(ERROR_EXPERIMENTER_SIZE, 16).
-define(HELLO_SIZE, 8).
-define(ECHO_REQUEST_SIZE, 8).
-define(ECHO_REPLY_SIZE, 8).
-define(EXPERIMENTER_SIZE, 16).

%% Structure sizes (in bytes) --------------------------------------------------

-define(PORT_SIZE, 64).
-define(PACKET_QUEUE_SIZE, 16).
-define(QUEUE_PROP_MIN_RATE_SIZE, 16).
-define(QUEUE_PROP_MAX_RATE_SIZE, 16).
-define(QUEUE_PROP_EXPERIMENTER_SIZE, 16).
-define(OXM_FIELD_SIZE, 4).
-define(MATCH_SIZE, 8).
-define(INSTRUCTION_GOTO_TABLE_SIZE, 8).
-define(INSTRUCTION_WRITE_METADATA_SIZE, 24).
-define(INSTRUCTION_WRITE_ACTIONS_SIZE, 8).
-define(INSTRUCTION_APPLY_ACTIONS_SIZE, 8).
-define(INSTRUCTION_CLEAR_ACTIONS_SIZE, 8).
-define(INSTRUCTION_EXPERIMENTER_SIZE, 8).
-define(ACTION_COPY_TTL_IN_SIZE, 8).
-define(ACTION_POP_MPLS_SIZE, 8).
-define(ACTION_POP_VLAN_SIZE, 8).
-define(ACTION_PUSH_MPLS_SIZE, 8).
-define(ACTION_PUSH_VLAN_SIZE, 8).
-define(ACTION_COPY_TTL_OUT_SIZE, 8).
-define(ACTION_DEC_MPLS_TTL_SIZE, 8).
-define(ACTION_DEC_NW_TTL_SIZE, 8).
-define(ACTION_SET_MPLS_TTL_SIZE, 8).
-define(ACTION_SET_NW_TTL_SIZE, 8).
-define(ACTION_SET_FIELD_SIZE, 8).
-define(ACTION_SET_QUEUE_SIZE, 8).
-define(ACTION_GROUP_SIZE, 8).
-define(ACTION_OUTPUT_SIZE, 16).
-define(ACTION_EXPERIMENTER_SIZE, 8).
-define(BUCKET_SIZE, 16).
-define(BUCKET_COUNTER_SIZE, 16).
-define(FLOW_STATS_SIZE, 56).
-define(TABLE_STATS_SIZE, 128).
-define(PORT_STATS_SIZE, 104).
-define(QUEUE_STATS_SIZE, 32).
-define(GROUP_STATS_SIZE, 32).
-define(GROUP_DESC_STATS_SIZE, 8).

%% Field lengths (in bits) -----------------------------------------------------

-define(IN_PORT_FIELD_LENGTH, 32).
-define(IN_PHY_PORT_FIELD_LENGTH, 32).
-define(METADATA_FIELD_LENGTH, 64).
-define(ETH_DST_FIELD_LENGTH, 48).
-define(ETH_SRC_FIELD_LENGTH, 48).
-define(ETH_TYPE_FIELD_LENGTH, 16).
-define(VLAN_VID_FIELD_LENGTH, 13).
-define(VLAN_PCP_FIELD_LENGTH, 3).
-define(IP_DSCP_FIELD_LENGTH, 6).
-define(IP_ECN_FIELD_LENGTH, 2).
-define(IP_PROTO_FIELD_LENGTH, 8).
-define(IPV4_SRC_FIELD_LENGTH, 32).
-define(IPV4_DST_FIELD_LENGTH, 32).
-define(TCP_SRC_FIELD_LENGTH, 16).
-define(TCP_DST_FIELD_LENGTH, 16).
-define(UDP_SRC_FIELD_LENGTH, 16).
-define(UDP_DST_FIELD_LENGTH, 16).
-define(SCTP_SRC_FIELD_LENGTH, 16).
-define(SCTP_DST_FIELD_LENGTH, 16).
-define(ICMPV4_TYPE_FIELD_LENGTH, 8).
-define(ICMPV4_CODE_FIELD_LENGTH, 8).
-define(ARP_OP_FIELD_LENGTH, 16).
-define(ARP_SPA_FIELD_LENGTH, 32).
-define(ARP_TPA_FIELD_LENGTH, 32).
-define(ARP_SHA_FIELD_LENGTH, 48).
-define(ARP_THA_FIELD_LENGTH, 48).
-define(IPV6_SRC_FIELD_LENGTH, 128).
-define(IPV6_DST_FIELD_LENGTH, 128).
-define(IPV6_FLABEL_FIELD_LENGTH, 20).
-define(ICMPV6_TYPE_FIELD_LENGTH, 8).
-define(ICMPV6_CODE_FIELD_LENGTH, 8).
-define(IPV6_ND_TARGET_FIELD_LENGTH, 128).
-define(IPV6_ND_SLL_FIELD_LENGTH, 48).
-define(IPV6_ND_TLL_FIELD_LENGTH, 48).
-define(MPLS_LABEL_FIELD_LENGTH, 20).
-define(MPLS_TC_FIELD_LENGTH, 3).

%% Misc sizes (in bytes) -------------------------------------------------------

-define(OFP_ETH_ALEN, 6).            %% ethernet address
-define(OFP_MAX_PORT_NAME_LEN, 16).  %% port name string
-define(OFP_MAX_TABLE_NAME_LEN, 32). %% table name string
-define(DESC_STR_LEN, 256).          %% switch description string
-define(SERIAL_NUM_LEN, 32).         %% serial number string
