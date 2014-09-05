-module(ofp_optical_ports).

-include_lib("eunit/include/eunit.hrl").
-include("of_protocol.hrl").
-include("ofp_v4.hrl").

ofp_multipart_request_test() ->
    F = [
        #ofp_port_optical_transport_feature_header{
            feature_type = 1,
            length = 1
        }
    ],
    B = #ofp_port_desc_prop_optical_transport{
        type = 1,
        length = 2,
        port_signal_type = 3,
        reserved = 4,
        features = F
    }, 
    Msg=
    #ofp_message{
        version = 4,
        type    = multipart_request,
        xid     = 12345,
        body    = B
    },
    {ok,EMsg} = of_protocol:encode(Msg),
    {ok,DMsg} = of_protocol:decode(EMsg),
    ?assertEqual(Msg,DMsg).

