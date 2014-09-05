-module(dummy).
-compile(export_all).

-include("../include/of_protocol.hrl").
-include("../include/ofp_v4.hrl").

-define(N,'loom@127.0.0.1').
-define(V,4).


t() ->
    F = [#ofp_port_optical_transport_feature_header { 
            feature_type=0 
    }],
    Pr = [#ofp_port_desc_prop_optical_transport {
            type=optical_transport,
            port_signal_type=0,
            reserved=0,
            features = F
    }],
    P = [#ofp_port_v6{
            port_no = 1,
            hw_addr = <<8,0,39,255,136,50>>,
            name = <<"Port1">>,
            config = [],
            state = [live],
            properties = Pr
    }],
    Data = #ofp_port_desc_reply_v6 { body = P },

    EncData = ofp_v4_encode:encode_body(Data),

    % <<
    % TypeInt:16,
    % FlagsBin/bytes,
    % 0:32,
    % <<
    %     PortNoInt:32, 
    %     Length:16, 
    %     0:16,
    %     HWAddr:?OFP_ETH_ALEN/bytes, 
    %     0:16,
    %     NameBin:?OFP_MAX_PORT_NAME_LEN/bytes,
    %     ConfigBin:4/bytes, 
    %     StateBin:4/bytes,
    %     <<
    %         TypeInt:16, 
    %         Length:16, 
    %         PortSigType:8, 
    %         Reserved:8, 
    %         0:16, 
    %         <<
    %             FeatureType:16, 
    %             Length:16
    %         >>/bytes
    %     >>/binary
    % >>/bytes
    % >>;
    
    %% Data    = ofp_v4_decode:decode_body(multipart_reply,EncData).

    % Enc:
    % encode_body(#ofp_port_desc_reply_v6{flags = Flags, body = Ports}) ->
    % TypeInt = ofp_v4_enum:to_int(multipart_type, port_desc_v6),
    % FlagsBin = flags_to_binary(multipart_reply_flags, Flags, 2),
    % PortsBin = encode_list(Ports),
    % <<TypeInt:16, FlagsBin/bytes, 0:32, PortsBin/bytes>>;

    Msg = #ofp_message{ 
        version = ?V,
        type = multipart_reply,
        xid = 1,
        body = #ofp_experimenter_reply{
            experimenter = 1,
            exp_type = 1,
            data = EncData
        }
    },

    {ok,EM}      = of_protocol:encode(Msg),
    {ok,DE,<<>>} = of_protocol:decode(EM),

    Msg = DE,

    DEB = DE#ofp_message.body,
    % %%io:format("DEB : ~p\n",[DEB]),

    BinData = DEB#ofp_experimenter_reply.data,
    io:format("BinData :~p\n\n",[BinData]),
    DecData = ofp_v4_decode:decode_body(multipart_reply,BinData).
    % io:format("DecData : ~p\n",[DecData]),

    % DE#ofp_message{ 
    %     body = DEB#ofp_experimenter_reply{ data = DecData } 
    % }.