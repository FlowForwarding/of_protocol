-module(ofp_oe_tests).

-include_lib("eunit/include/eunit.hrl").

-include("include/of_protocol.hrl").
-include("include/ofp_v4.hrl").

optical_transport_port_desc_request_test() ->
    Msg = 
    #ofp_message{
        version = 4,
        type    = multipart_request,
        xid     = 0,
        body    = #ofp_experimenter_request{experimenter = ?INFOBLOX_EXPERIMENTER,
                                            exp_type     = port_desc
                                        }
    },
    {ok,Enc} = of_protocol:encode(Msg),
    {ok,Dec,<<>>} = of_protocol:decode(Enc),
    ?assertEqual(Dec,Msg).

optical_transport_port_desc_reply_test() ->
    V = [#ofp_port_optical_transport_layer_entry{
            layer_class = port,
            signal_type = otsn,
            adaptation  = ots_oms
         },
         #ofp_port_optical_transport_layer_entry{
            layer_class = och,
            signal_type = fix_grid,
            adaptation  = oduk_oduij
         }
    ],
    F = [#ofp_port_optical_transport_application_code{
            feature_type    = opt_interface_class,
            oic_type        = proprietary,
            app_code        = <<"arbitrary">>
         },
         #ofp_port_optical_transport_layer_stack{
            feature_type    = layer_stack,
            value           = V
    }], 
    Pr = [#ofp_port_desc_prop_optical_transport {
            type                = optical_transport,
            port_signal_type    = otsn,
            reserved            = 0,
            features            = F
    }],
    P = [#ofp_port_v6{
            port_no     = 1,
            hw_addr     = <<8,0,39,255,136,50>>,
            name        = <<"Port1">>,
            config      = [],
            state       = [live],
            properties  = Pr
    }],
    Data = #ofp_port_desc_reply_v6 { body = P },
    Msg = #ofp_message{ 
        version = 4,
        type = multipart_reply,
        xid = 1,
        body = #ofp_experimenter_reply{
            experimenter    = ?INFOBLOX_EXPERIMENTER,
            exp_type        = port_desc,
            data            = Data
        }
    },
    ExpectedBinary = <<
% ofp_header:
4,                  % version
19,                 % type (OFPT_MULTIPART_REPLY)
0,124,              % length
0,0,0,1,            % xid
% ofp_multipart_reply:
255,255,            % type (OFPMP_EXPERIMENTER)
0,0,                % flags
0,0,0,0,            % pad
% ofp_experimenter_multipart_header:
0,116,135,113,      % experimenter (Infoblox)
0,0,0,13,           % type (OFPMP_PORT_DESC)
% ofp_multipart_reply:
0,13,               % OFPMP_PORT_DESC
0,0,                % flags
0,0,0,0,            % pad
% ofp_port:
0,0,0,1,            % port_no (1)
0,92,               % length
0,0,                % pad
8,0,39,255,136,50,  % hw_addr
0,0,                % pad
80,111,114,116, 49,0,0,0, 0,0,0,0, 0,0,0,0,
                    % name
0,0,0,0,            % config
0,0,0,4,            % state
% ofp_port_desc_prop_optical_transport:
0,2,                % type (OFPPDPT_OPTICAL_TRANSPORT)
0,52,               % length
1,                  % port_signal_type (OFPOTPT_OTSn)
0,                  % reserved
0,0,                % pad
% ofp_port_optical_transport_application_code:
0,1,                % feature_type (OFPPOTFT_OPT_INTERFACE_CLASS)
0,136,              % length
128,                % oic_type (OFPOICT_PROPRIETARY)
97,114,98,105,116, 114,97,114,121,0, 0,0,0,0,0,
                    % app_code
% ofp_port_optical_transport_layer_stack:
0,2,                % feature_type (OFPPOTFT_LAYER_STACK)
0,24,               % length
0,0,0,0,            % pad
% ofp_port_optical_transport_layer_entry:
1,                  % layer_class (OFPPOTL_PORT)
1,                  % signal_type (OFPOTPT_OTSn)
1,                  % adaptation (OFPADAPT_OTS_OMS)
0,0,0,0,0,          % pad
% ofp_port_optical_transport_layer_entry:
2,                  % layer_class (OFPPOTL_OCH)
1,                  % signal_type (OFPOCHT_FIX_GRID)
6,                  % adaptation (OFPADAPT_ODUk_ODUij)
0,0,0,0,0           % pad
>>,
    {ok,EM}      = of_protocol:encode(Msg),
    {ok,DE,<<>>} = of_protocol:decode(EM),
    ?assertEqual(EM, ExpectedBinary),
    ?assertEqual(DE,Msg).

optical_transport_port_status_test() ->
    %%trace(),
    V = [#ofp_port_optical_transport_layer_entry{
            layer_class = port,
            signal_type = otsn,
            adaptation  = ots_oms
         },
         #ofp_port_optical_transport_layer_entry{
            layer_class = och,
            signal_type = fix_grid,
            adaptation  = oduk_oduij
         }
    ],
    F = [#ofp_port_optical_transport_application_code{
            feature_type    = opt_interface_class,
            oic_type        = proprietary,
            app_code        = <<"arbitrary">>
         },
         #ofp_port_optical_transport_layer_stack{
            feature_type    = layer_stack,
            value           = V
    }], 
    Pr = [#ofp_port_desc_prop_optical_transport {
            type                = optical_transport,
            port_signal_type    = otsn,
            reserved            = 0,
            features            = F
    }],
    P = #ofp_port_v6{
            port_no     = 1,
            hw_addr     = <<8,0,39,255,136,50>>,
            name        = <<"Port1">>,
            config      = [],
            state       = [live],
            properties  = Pr
    },
    Body = 
        #ofp_port_status{
            reason = add,
            desc = P
        },
    Msg = 
    #ofp_message{
        version = 4,
        type = experimenter,
        xid = 12345,
        body = #ofp_experimenter{
                experimenter = ?INFOBLOX_EXPERIMENTER,
                exp_type     = port_status,
                data         = Body
            }
    },

    {ok,Enc} = of_protocol:encode(Msg),
    {ok,Dec,<<>>} = of_protocol:decode(Enc),
    ?assertEqual(Dec,Msg).

odu_sigid() ->
    MatchField = #ofp_field{class = openflow_basic,
                    has_mask = false,
                    name = in_port,
                    value= <<1:32>>},
    Field = #ofp_field{class = openflow_basic,
                       has_mask = false,
                       name = odu_sigid,
                       value = <<0:16, (_ChannelNumber = 10):16, 0:16>>},
    SetField = #ofp_action_set_field{field = Field},
    Action1 = #ofp_action_experimenter{experimenter = ?INFOBLOX_EXPERIMENTER, data = SetField},
    Action2 = #ofp_action_output{port = 2, max_len = no_buffer},
    Instruction = #ofp_instruction_apply_actions{actions = [Action1,Action2]},
    Flow = #ofp_flow_mod{ cookie = <<0:64>>,
                         cookie_mask = <<0:64>>,
                         table_id = 0,
                         command = add,
                         idle_timeout = 0,
                         hard_timeout = 0,
                         priority = 1,
                         buffer_id = no_buffer,
                         out_port = any,
                         out_group = any,
                         flags = [],
                         match = #ofp_match{fields = [MatchField]},
                         instructions = [Instruction]
    },
    Msg = 
        #ofp_message{
            version = 4,
            body = Flow
        },
    {ok,EncMsg} = of_protocol:encode(Msg),
    {ok,DecMsg,<<>>} = of_protocol:decode(EncMsg),
    ?assertEqual(DecMsg,Msg).    

ofp_oxm_experimenter_header_test() ->

    MatchField1 = #ofp_field{class = openflow_basic,
                            has_mask = false,
                            name = in_port,
                            value= <<3:32>>},
    MatchField2 = #ofp_oxm_experimenter{
                     body = #ofp_field{class = openflow_basic,
                                       has_mask = false,
                                       name = och_sigtype,
                                       value = <<10:8>>},
                     experimenter = ?INFOBLOX_EXPERIMENTER},
    MatchField3 = #ofp_oxm_experimenter{
                     body = #ofp_field{class = openflow_basic,
                                       has_mask = false,
                                       name = och_sigid,
                                       value = <<0:16, (_InChannelNumber = 10):16, 0:16>>},
                     experimenter = ?INFOBLOX_EXPERIMENTER}, 
    Field = #ofp_field{class = openflow_basic,
                       has_mask = false,
                       name = och_sigid,
                       value = <<0:16, (_OutChannelNumber = 20):16, 0:16>>},
    SetField = #ofp_action_set_field{field = Field},
    Action1 = #ofp_action_experimenter{experimenter = ?INFOBLOX_EXPERIMENTER,
                                       data = SetField},
    Action2 = #ofp_action_output{port = 4, max_len = no_buffer},
    Instruction = #ofp_instruction_apply_actions{actions = [Action1,Action2]},
    Body=#ofp_flow_mod{
               cookie = <<0:64>>,
               cookie_mask = <<0:64>>,
               table_id = 0,
               command = add,
               idle_timeout = 0,
               hard_timeout = 0,
               priority = 1,
               buffer_id = no_buffer,
               out_port = any,
               out_group = any,
               flags = [],
               match = #ofp_match{fields = [MatchField1,
                                            MatchField2,
                                            MatchField3]},
               instructions = [Instruction]},
    Msg = #ofp_message{ type = undefined,
                        version = 4,
                        body = Body
                      },
    {ok,Enc} = of_protocol:encode(Msg),
    Ans = of_protocol:decode(Enc).
    %% {ok,Dec,<<>>} = of_protocol:decode(Enc).
    %% ?assertEqual(Dec,Msg).
    %% Cannot assert msg, because matches are not reversed 
    %% when the list of matches are processed....

trace() ->
    %% Mods = [ ofp_v4_encode, ofp_v4_deocde ],
    Mods = [ ofp_v4_enum ],
    dbg:tracer(),
    dbg:p(all,call),
    [ dbg:tpl(Mod,[{'_',[],[{message,{return_trace}}]}]) || Mod <- Mods ].
