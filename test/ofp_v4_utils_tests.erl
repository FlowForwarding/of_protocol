-module(ofp_v4_utils_tests).

-include_lib("eunit/include/eunit.hrl").

mk_msg_flow_add_test() ->
    _ = ofp_v4_utils:mk_msg({flow_add,
                             [],
                             {matching, [{eth_type, <<16#0800:16>>}]},
                             {instructions, [clear_actions]}}).

mk_msg_flow_del_test() ->
    _ = ofp_v4_utils:mk_msg({flow_del,
                             [],
                             {matching, [{eth_type, <<16#0800:16>>}]}}).

mk_msg_flow_del_strict_test() ->
    _ = ofp_v4_utils:mk_msg({flow_del_strict,
                             [],
                             {matching, [{eth_type, <<16#0800:16>>}]}}).
