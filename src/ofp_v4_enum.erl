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
%% @author Konrad Kaplita <Konrad Kaplita@erlang-solutions.com>
%% @author Krzysztof Rutka <krzysztof.rutka@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org
%% @doc OpenFlow Protocol 1.3 (4) enumerations.
%% @private
-module(ofp_v4_enum).

%%------------------------------------------------------------------------------
%% OpenFlow Header (A.1)
%%------------------------------------------------------------------------------

-enum({type, [%% Immutable messages
              hello,
              error,
              echo_request,
              echo_reply,
              experimenter,
              %% Switch configuration messages
              features_request,
              features_reply,
              get_config_request,
              get_config_reply,
              set_config,
              %% Asynchronous messages
              packet_in,
              flow_removed,
              port_status,              
              %% Controller command messages
              packet_out,
              flow_mod,
              group_mod,
              port_mod,
              table_mod,
              %% Multipart messages
              multipart_request,
              multipart_reply,
              %% Barrier messages
              barrier_request,
              barrier_reply,
              %% Queue configuration messages
              queue_get_config_request,
              queue_get_config_reply,
              %% Controller role change request messages
              role_request,
              role_reply,
              %% Asynchronous message configuration
              get_async_request,
              get_async_reply,
              set_async,
              %% Meters and rate limiters configuration messages
              meter_mod
             ]}).

%%------------------------------------------------------------------------------
%% Common Structures
%%------------------------------------------------------------------------------

%% Port Structures -------------------------------------------------------------

-enum({port_config, [port_down,
                     {no_recv, 2},
                     {no_fwd, 5},
                     no_packet_in]}).

-enum({port_state, [link_down,
                    blocked,
                    live]}).

-enum({port_no, [{in_port, 16#fffffff8},
                 {table, 16#fffffff9},
                 normal,
                 flood,
                 all,
                 controller,
                 local,
                 any]}).

-enum({port_features, ['10mb_hd',
                       '10mb_fd',
                       '100mb_hd',
                       '100mb_fd',
                       '1gb_hd',
                       '1gb_fd',
                       '10gb_fd',
                       '40gb_fd',
                       '100gb_fd',
                       '1tb_fd',
                       other,
                       copper,
                       fiber,
                       autoneg,
                       pause,
                       pause_asym]}).

%% Queue Structures ------------------------------------------------------------

%% Note: Not in the specification
-enum({queue, [{all, 16#ffffffff}]}).

-enum({queue_properties, [min_rate,
                          max_rate,
                          {experimenter, 16#ffff}]}).

%% Flow Match Structures -------------------------------------------------------

-enum({match_type, [standard,
                    oxm]}).

-enum({oxm_class, [nxm_0,
                   nxm_1,
                   {openflow_basic, 16#8000},
                   {experimenter, 16#ffff}]}).

-enum({oxm_ofb_match_fields, [in_port,
                              in_phy_port,
                              metadata,
                              eth_dst,
                              eth_src,
                              eth_type,
                              vlan_vid,
                              vlan_pcp,
                              ip_dscp,
                              ip_ecn,
                              ip_proto,
                              ipv4_src,
                              ipv4_dst,
                              tcp_src,
                              tcp_dst,
                              udp_src,
                              udp_dst,
                              sctp_src,
                              sctp_dst,
                              icmpv4_type,
                              icmpv4_code,
                              arp_op,
                              arp_spa,
                              arp_tpa,
                              arp_sha,
                              arp_tha,
                              ipv6_src,
                              ipv6_dst,
                              ipv6_flabel,
                              icmpv6_type,
                              icmpv6_code,
                              ipv6_nd_target,
                              ipv6_nd_sll,
                              ipv6_nd_tll,
                              mpls_label,
                              mpls_tc,
                              mpls_bos,
                              pbb_isid,
                              tunnel_id,
                              ipv6_exthdr]}).

-enum({vlan_id, [none,
                 {present, 16#1000}]}).

%% Flow Instruction Structures -------------------------------------------------

-enum({instruction_type, [{goto_table, 1},
                          write_metadata,
                          write_actions,
                          apply_actions,
                          clear_actions,
                          meter,
                          {experimenter, 16#ffff}]}).

%% Action Structures -----------------------------------------------------------

-enum({action_type, [output,
                     {copy_ttl_out, 11},
                     copy_ttl_in,
                     {set_mpls_ttl, 15},
                     dec_mpls_ttl,
                     push_vlan,
                     pop_vlan,
                     push_mpls,
                     pop_mpls,
                     push_pbb,
                     pop_pbb,
                     set_queue,
                     group,
                     set_nw_ttl,
                     dec_nw_ttl,
                     set_field,
                     {experimenter, 16#ffff}]}).

%%------------------------------------------------------------------------------
%% Controller-to-Switch Messages
%%------------------------------------------------------------------------------

%% Handshake -------------------------------------------------------------------

-enum({capabilities, [flow_stats,
                      table_stats,
                      port_stats,
                      group_stats,
                      {ip_reasm, 5},
                      queue_stats,
                      {port_blocked, 8}]}).

%% Switch Configuration --------------------------------------------------------

-enum({config_flags, [frag_drop,
                      frag_reasm,
                      invalid_ttl_to_controller]}).

%% Flow Table Configuration ----------------------------------------------------

-enum({table, [{all, 16#ff}]}).

-enum({table_config, [continue,
                      drop]}).

%% Modify State Messages -------------------------------------------------------

%% Note: Not in the specification
-enum({buffer, [{no_buffer, 16#ffff}]}).

-enum({flow_mod_command, [add,
                          modify,
                          modify_strict,
                          delete,
                          delete_strict]}).

-enum({flow_mod_flags, [send_flow_rem,
                        check_overlap,
                        reset_counts,
                        no_pkt_counts,
                        no_byt_counts]}).

%% Note: Not in the specification
-enum({group, [{any, 16#fffffffe},
               all]}).

-enum({group_mod_command, [add,
                           modify,
                           delete]}).

-enum({group_type, [all,
                    select,
                    indirect,
                    ff]}).

-enum({meter_mod_command, [add,
                           modify,
                           delete]}).

-enum({meter_flag, [kbps,
                    pktps,
                    burst,
                    stats]}).

-enum({meter_id, [{slowpath, 16#fffffffd},
                  {controller, 16#fffffffe},
                  {all, 16#ffffffff}]}).

-enum({meter_band_type, [drop,
                         dscp_remark,
                         {experimenter, 16#ffff}]}).

%% Read State Messages ---------------------------------------------------------

-enum({stats_request_flags, []}).

-enum({stats_reply_flags, [{more, 1}]}).

-enum({stats_type, [desc,
                    flow,
                    aggregate,
                    table,
                    port,
                    queue,
                    group,
                    group_desc,
                    group_features,
                    {experimenter, 16#ffff}]}).

-enum({group_capabilities, [select_weight,
                            select_liveness,
                            chaining,
                            chaining_checks]}).

%% Queue Configuration Messages ------------------------------------------------

%% Packet-Out Messages ---------------------------------------------------------

%% Barrier Messages ------------------------------------------------------------

%% Role Request Messages -------------------------------------------------------

-enum({controller_role, [nochange,
                         equal,
                         master,
                         slave]}).

%%------------------------------------------------------------------------------
%% Asynchronous Messages
%%------------------------------------------------------------------------------

%% Packet-In Message -----------------------------------------------------------

-enum({packet_in_reason, [no_match,
                          action,
                          invalid_ttl]}).

%% Flow Removed Message --------------------------------------------------------

-enum({flow_removed_reason, [idle_timeout,
                             hard_timeout,
                             delete,
                             group_delete]}).

%% Port Status Message ---------------------------------------------------------

-enum({port_reason, [add,
                     delete,
                     modify]}).

%% Error Message ---------------------------------------------------------------

-enum({error_type, [hello_failed,
                    bad_request,
                    bad_action,
                    bad_instruction,
                    bad_match,
                    flow_mod_failed,
                    group_mod_failed,
                    port_mod_failed,
                    table_mod_failed,
                    queue_op_failed,
                    switch_config_failed,
                    role_request_failed,
                    meter_mod_failed,
                    table_features_failed,
                    {experimenter, 16#ffff}]}).

-enum({hello_failed, [incompatible,
                      eperm]}).

-enum({bad_request, [bad_version,
                     bad_type,
                     bad_multipart,
                     bad_experimenter,
                     bad_exp_type,
                     eperm,
                     bad_len,
                     buffer_empty,
                     buffer_unknown,
                     bad_table_id,
                     is_slave,
                     bad_port,
                     bad_packet,
                     multipart_buffer_overflow]}).

-enum({bad_action, [bad_type,
                    bad_len,
                    bad_experimenter,
                    bad_exp_type,
                    bad_out_port,
                    bad_argument,
                    eperm,
                    too_many,
                    bad_queue,
                    bad_out_group,
                    match_inconsistent,
                    unsupported_order,
                    bad_tag,
                    bad_set_type,
                    bad_set_len,
                    bad_set_argument]}).

-enum({bad_instruction, [unknown_inst,
                         unsup_inst,
                         bad_table_id,
                         unsup_metadata,
                         unsup_metadata_mask,
                         bad_experimenter,
                         bad_exp_type,
                         bad_len,
                         eperm]}).

-enum({bad_match, [bad_type,
                   bad_len,
                   bad_tag,
                   bad_dl_addr_mask,
                   bad_nw_addr_mask,
                   bad_wildcards,
                   bad_field,
                   bad_value,
                   bad_mask,
                   bad_prereq,
                   dup_field,
                   eperm]}).

-enum({flow_mod_failed, [unknown,
                         table_full,
                         bad_table_id,
                         overlap,
                         eperm,
                         bad_timeout,
                         bad_command,
                         bad_flags]}).

-enum({group_mod_failed, [group_exists,
                          invalid_group,
                          weight_unsupported,
                          out_of_groups,
                          out_of_buckets,
                          chaining_unsupported,
                          watch_unsupported,
                          loop,
                          unknown_group,
                          chained_group,
                          bad_type,
                          bad_command,
                          bad_bucket,
                          bad_watch,
                          eperm]}).

-enum({port_mod_failed, [bad_port,
                         bad_hw_addr,
                         bad_config,
                         bad_advertise,
                         eperm]}).

-enum({table_mod_failed, [bad_table,
                          bad_config,
                          eperm]}).

-enum({queue_op_failed, [bad_port,
                         bad_queue,
                         eperm]}).

-enum({switch_config_failed, [bad_flags,
                              bad_len,
                              eperm]}).

-enum({role_request_failed, [stale,
                             unsup,
                             bad_role]}).

-enum({meter_mod_failed, [unknown,
                          meter_exists,
                          invalid_meter,
                          unknown_meter,
                          bad_command,
                          bad_flags,
                          bad_rate,
                          bad_burst,
                          bad_band,
                          bad_band_value,
                          out_of_meters,
                          out_of_bands]}).

-enum({table_features_failed, [bad_table,
                               bad_metadata,
                               bad_type,
                               bad_len,
                               bad_argument,
                               eperm]}).

%%------------------------------------------------------------------------------
%% Symmetric Messages
%%------------------------------------------------------------------------------

%% Hello -----------------------------------------------------------------------

%% Echo Request ----------------------------------------------------------------

%% Echo Reply ------------------------------------------------------------------

%% Experimenter ----------------------------------------------------------------
