-module(ofp_v5_encode_tests).

-define(NOTEST, true).
-define(NOASSERT, true).
-include_lib("eunit/include/eunit.hrl").
-include("of_protocol.hrl").
-include("ofp_v5.hrl").

-define(MODNAME, ofp_v5_encode).

flow_monitor_req_test() ->
    Msg = #ofp_message{version = 5,
                       type    = multipart_request,
                       xid     = 765,
                       body    = #ofp_flow_monitor_request{
                         flags      = [],
                         monitor_id = 1,
                         out_port   = any,
                         out_group  = any,
                         monitor_flags = [initial, add, removed, modify,
                                          instructions, no_abbrev, only_own],
                         table_id   = 0,
                         command    = add,
                         match      = #ofp_match{
                           fields = [#ofp_field{
                                        class    = openflow_basic,
                                        name     = ip_proto,
                                        has_mask = false,
                                        value    = <<50:8>>,
                                        mask     = undefined
                                       }
                                    ]}
                        }
                      },
    {ok, EMsg} = of_protocol:encode(Msg),
    {ok, DMsg, <<>>} = of_protocol:decode(EMsg),
    ?assertEqual(Msg, DMsg).

flow_updates_test() ->
    Msg = #ofp_message{version = 5,
                       type    = multipart_reply,
                       xid     = 0,
                       body    = #ofp_flow_monitor_reply{
                         flags = [],
                         updates = [#ofp_flow_update_full{
                                       event             = modified,
                                       table_id          = 8,
                                       reason            = meter_delete,
                                       idle_timeout      = 785,
                                       hard_timeout      = 12541,
                                       priority          = 2,
                                       cookie            = <<15111223353:64>>,
                                       match             = #ofp_match{
                                         fields = [#ofp_field{
                                                      class    = openflow_basic,
                                                      name     = ip_proto,
                                                      has_mask = false,
                                                      value    = <<50:8>>,
                                                      mask     = undefined}
                                                  ]},
                                       instructions = [#ofp_instruction_clear_actions{},
                                                       #ofp_instruction_goto_table{table_id = 2}]},
                                    #ofp_flow_update_abbrev{
                                                           event = abbrev,
                                                           xid = 135657}
                                 ]}},
    {ok, EMsg} = of_protocol:encode(Msg),
    {ok, DMsg, _Rest} = of_protocol:decode(EMsg),
    ?assertEqual(Msg, DMsg).

flow_update_paused_test() ->
    Msg = #ofp_message{version = 5,
                       type    = multipart_reply,
                       xid     = 0,
                       body    = #ofp_flow_monitor_reply{
                         flags = [],
                         updates = [#ofp_flow_update_paused{event = resumed}]}},
    {ok, EMsg} = of_protocol:encode(Msg),
    {ok, DMsg, _Rest} = of_protocol:decode(EMsg),
    ?assertEqual(Msg, DMsg).

packet_in_test() ->
    TotalLen = 50,
    Msg = #ofp_message{version = 5,
                       type = packet_in,
                       xid = 0,
                       body = #ofp_packet_in{
                                 buffer_id = 10,
                                 total_len = TotalLen,
                                 reason = apply_action,
                                 table_id = 0,
                                 cookie = <<10:64>>,
                                 match = #ofp_match{
                                            fields = [#ofp_field{
                                                         class  = openflow_basic,
                                                         name = in_port,
                                                         has_mask = false,
                                                         value = <<1:32>>,
                                                         mask = undefined}]},
                                 data = << <<X>>
                                           || X <- lists:seq(1, TotalLen - 20) >>}},
    {ok, EMsg} = of_protocol:encode(Msg),
    {ok, DMsg, _Rest} = of_protocol:decode(EMsg),
    ?assertEqual(Msg, DMsg).
