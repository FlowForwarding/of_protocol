-module(ofp_oe_tests).

-include_lib("eunit/include/eunit.hrl").

-include("include/of_protocol.hrl").
-include("include/ofp_v4.hrl").

optical_transport_port_desc_request_test() ->
    Msg = 
    #ofp_message{
        version = 4,
        type = multipart_request,
        xid = 0,
        body = #ofp_experimenter_request{experimenter = 0,
                                         exp_type     = 0
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
            oic_type        = proprietary,
            app_code        = "arbitrary"
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
    EncData = ofp_v4_encode:encode_body(Data),
    Msg = #ofp_message{ 
        version = 4,
        type = multipart_reply,
        xid = 1,
        body = #ofp_experimenter_reply{
            experimenter    = 1,
            exp_type        = 1,
            data            = EncData
        }
    },
    {ok,EM}      = of_protocol:encode(Msg),
    {ok,DE,<<>>} = of_protocol:decode(EM),
    ?assertEqual(DE,Msg).

    % TODO: decode and test inside bodies....

    % BinData = (DE#ofp_message.body)#ofp_experimenter_reply.data,
    % DecData2 = ofp_v4_decode:decode_body(multipart_reply,BinData),
    %% ?assertEqual(DecData,DecData2).

optical_transport_port_status_test() ->
    %% Async to controller
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
    EncStruct = ofp_v4_encode:encode_struct(P),
    DecStruct = ofp_v4_decode:decode_port_v6(EncStruct),

    ?assertEqual(P,DecStruct),

    Body = 
        #ofp_port_status{
            reason = add,
            desc = P
        },
    EncData = ofp_v4_encode:encode_body(Body),
    DecData = ofp_v4_decode:decode_body(port_status_v6,EncData),

    ?assertEqual(Body,DecData),

    Msg = 
    #ofp_message{
        version = 4,
        type = experimenter,
        xid = 12345,
        body = #ofp_experimenter{
                experimenter = 1,
                exp_type = 1,
                data = EncData
            }
    },
    {ok,Enc}      = of_protocol:encode(Msg),
    {ok,Dec,<<>>} = of_protocol:decode(Enc),

    ?assertEqual(Dec,Msg).
