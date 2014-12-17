-module(ofp_v5_utils).

-compile(export_all).

-include("of_protocol.hrl").
-include("ofp_v5.hrl").

mk_msg({flow_add, Opts, {matching,Ms}, {instructions,Is}}) ->
    message(flow_add(Opts, Ms, Is));
mk_msg({flow_del, Opts, {matching,Ms}}) ->
    message(flow_delete(delete,
                        Opts, 
                        match(mk_matches(Ms))));
mk_msg({flow_del_strict,Opts, {matching,Ms}}) ->
    message(flow_delete(delete_strict,
                        Opts, 
                        match(mk_matches(Ms)))).

message(Body) ->
    #ofp_message{xid=1,body=Body}.

%%============================================================================
%% Flow admin

flow_add(Opts, Matches, Instructions) ->
    #ofp_flow_mod{
       cookie = proplists:get_value(cookie, Opts, <<0:64>>),
       cookie_mask = proplists:get_value(cookie_mask, Opts, <<0:64>>),
       table_id = proplists:get_value(table_id, Opts, 0),
       command = add,
       idle_timeout = proplists:get_value(idle_timeout, Opts, 0),
       hard_timeout = proplists:get_value(hard_timeout, Opts, 0),
       priority = proplists:get_value(priority, Opts, 16#ffff),
       buffer_id = proplists:get_value(buffer_id, Opts, no_buffer),
       flags = proplists:get_value(flags, Opts, []),
       match = match(mk_matches(Matches)),
       instructions = mk_instructions(Instructions)}.
flow_modify(Op, Opts, Matches, Instructions) ->
    #ofp_flow_mod{
       cookie = proplists:get_value(cookie, Opts, <<0:64>>),
       cookie_mask = proplists:get_value(cookie_mask, Opts, <<0:64>>),
       table_id = proplists:get_value(table_id, Opts, 0),
       command = Op,
       priority = proplists:get_value(priority, Opts, 16#ffff),
       flags = proplists:get_value(flags, Opts, []),
       match = match(mk_matches(Matches)),
       instructions = mk_instructions(Instructions)
      }.
flow_delete(Op, Opts, Matches) ->
    #ofp_flow_mod{
       cookie = proplists:get_value(cookie, Opts, <<0:64>>),
       cookie_mask = proplists:get_value(cookie_mask, Opts, <<0:64>>),
       table_id = proplists:get_value(table_id, Opts, 0),
       command = Op,
       priority = proplists:get_value(priority, Opts, 16#ffff),
       out_port = proplists:get_value(out_port, Opts, any),
       out_group = proplists:get_value(out_group, Opts, any),
       flags = proplists:get_value(flags, Opts, []),
       match = match(mk_matches(Matches))
      }.

flow_stats(Opts, Matches) ->
    #ofp_flow_stats_request{
       table_id = proplists:get_value(table_id, Opts, 0),
       cookie = proplists:get_value(cookie, Opts, <<0:64>>),
       cookie_mask = proplists:get_value(cookie_mask, Opts, <<0:64>>),
       out_port = proplists:get_value(out_port, Opts, any),
       out_group = proplists:get_value(out_group, Opts, any),
       match = match(mk_matches(Matches))
      }.

aggr_stats(Opts, Matches) ->
    #ofp_aggregate_stats_request{
       table_id = proplists:get_value(table_id, Opts, 0),
       cookie = proplists:get_value(cookie, Opts, <<0:64>>),
       cookie_mask = proplists:get_value(cookie_mask, Opts, <<0:64>>),
       out_port = proplists:get_value(out_port, Opts, any),
       out_group = proplists:get_value(out_group, Opts, any),
       match = match(mk_matches(Matches))
      }.
%%============================================================================
%% Matching
%% Create match specifications, checking that prerequisite fields are present
%% and if not adding them.

mk_matches(Ms) ->
    mk_matches(Ms,[]).

mk_matches([M|Ms], Acc) ->
    mk_matches(Ms, mk_match(M,Acc));
mk_matches([], Acc) ->
    lists:reverse(Acc).

mk_match({Field,Val}, Acc) ->
    Acc1 = add_required_fields(Field, Acc),
    [?MODULE:Field(Val)|Acc1];
mk_match({Field,Val,Mask}, Acc) ->
    [?MODULE:Field(Val,Mask)|Acc].

add_required_fields(Field, Acc) ->
    case required(Field) of
	{F,V} ->
	    case has_match(F,V,Acc) of
		missing ->
		    [?MODULE:F(V)|add_required_fields(F, Acc)];
		present ->
		    Acc
	    end;
	[{F1,V1},{F2,V2}]=M ->
	    case (has_match(F1,V1,Acc)==present) or (has_match(F2,V2,Acc)==present) of
		true ->
		    Acc;
		false ->
		    throw({missing_match,M})
	    end;
	none ->
	    Acc
    end.
    
    
has_match(Field, Val, Acc) ->
    case lists:keyfind(Field, #ofp_field.name, Acc) of
	#ofp_field{value=Val} ->
	    present;
	#ofp_field{} ->
	    other;
	false ->
	    missing
    end.
				      
required(in_phy_port) ->
    in_port;
required(vlan_pcp) ->
    %% this needs work
    {vlan_vid,none};
required(ip_dscp) ->
    [{eth_type,<<16#800:16>>},{eth_type,<<16#86dd:16>>}];
required(ip_ecn) ->
    [{eth_type,<<16#800:16>>},{eth_type,<<16#86dd:16>>}];
required(ip_proto) ->
    [{eth_type,<<16#800:16>>},{eth_type,<<16#86dd:16>>}];
required(ipv4_src) ->
    {eth_type,<<16#800:16>>};
required(ipv4_dst) ->
    {eth_type,<<16#800:16>>};
required(tcp_src) ->
    {ip_proto,<<6:8>>};
required(tcp_dst) ->
    {ip_proto,<<6:8>>};
required(udp_src) ->
    {ip_proto,<<17:8>>};
required(udp_dst) ->
    {ip_proto,<<17:8>>};
required(sctp_src) ->
    {ip_proto,<<132:8>>};
required(sctp_dst) ->
    {ip_proto,<<132:8>>};
required(icmpv4_type) ->
    {ip_proto,<<1:8>>};
required(icmpv4_code) ->
    {ip_proto,<<1:8>>};
required(arp_op) ->
    {eth_type,<<16#806:16>>};
required(arp_spa) ->
    {eth_type,<<16#806:16>>};
required(arp_tpa) ->
    {eth_type,<<16#806:16>>};
required(arp_sha) ->
    {eth_type,<<16#806:16>>};
required(arp_tha) ->
    {eth_type,<<16#806:16>>};
required(ipv6_src) ->
    {eth_type,<<16#86dd:16>>};
required(ipv6_dst) ->
    {eth_type,<<16#86dd:16>>};
required(ipv6_flabel) ->
    {eth_type,<<16#86dd:16>>};
required(icmpv6_type) ->
    {ip_proto,<<58:8>>};
required(icmpv6_code) ->
    {ip_proto,<<58:8>>};
required(ipv6_nd_target) ->
    [{icmpv6_type,<<135:8>>},{icmpv6_type,<<136:8>>}];
required(ipv6_nd_sll) ->
    {icmpv6_type,<<135:8>>};
required(ipv6_nd_tll) ->
    {icmpv6_type,<<136:8>>};
required(mpls_label) ->
    [{eth_type,<<16#8847:16>>},{eth_type,<<16#8848:16>>}];
required(mpls_tc) ->
    [{eth_type,<<16#8847:16>>},{eth_type,<<16#8848:16>>}];
required(mpls_bos) ->
    [{eth_type,<<16#8847:16>>},{eth_type,<<16#8848:16>>}];
required(pbb_isid) ->
    {eth_type,<<16#88E7:16>>};
required(ipv6_exthdr) ->
    {eth_type,<<16#86dd:16>>};
required(pbb_uca) ->
    {eth_type,<<16#88e7:16>>};
required(_) ->
    none.

%%===========================================================================
%% Matches

match(Fields) when is_list(Fields) ->
    #ofp_match{fields=Fields};
match(Field) ->
    #ofp_match{fields=[Field]}.

%% Fields
in_port(Val) when is_integer(Val) ->
    in_port(<<Val:32>>);
in_port(Val) when byte_size(Val)==4 ->
    #ofp_field{name = in_port,
	       value = Val}.
% in_port
in_phy_port(Val) when is_integer(Val) ->
    in_phy_port(<<Val:32>>);
in_phy_port(Val) when byte_size(Val)==4 ->
    #ofp_field{name = phy_port,
	      value = Val}.

metadata(Val) when byte_size(Val)==8 ->
    #ofp_field{name = metadata,
	      value = Val}.
metadata(Val, Mask) when byte_size(Val)==8, byte_size(Mask)==8  ->
    #ofp_field{name = metadata,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

eth_dst({M1,M2,M3,M4,M5,M6}) ->
    eth_dst(<<M1,M2,M3,M4,M5,M6>>);
eth_dst(Val) when byte_size(Val)==6 ->
    #ofp_field{name = eth_dst,
	      value = Val}.
eth_dst(Val, Mask) when byte_size(Val)==6 ->
    #ofp_field{name = eth_dst,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

eth_src({M1,M2,M3,M4,M5,M6}) ->
    eth_src(<<M1,M2,M3,M4,M5,M6>>);
eth_src(Val) when byte_size(Val)==6 ->
    #ofp_field{name = eth_src,
	      value = Val}.
eth_src(Val, Mask) when byte_size(Val)==6, byte_size(Mask)==6 ->
    #ofp_field{name = eth_src,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

eth_type(Val) when is_integer(Val) ->
    eth_type(<<Val:16>>);
eth_type(Val) when byte_size(Val)==2 ->
    #ofp_field{name = eth_type,
	      value = Val}.

vlan_vid(Val) when is_integer(Val) ->
    vlan_vid(<<Val:13>>);
vlan_vid(Val) ->
    #ofp_field{name = vlan_vid,
	      value = Val}.
vlan_vid(Val, Mask) when is_integer(Val), is_integer(Mask) ->
    vlan_vid(<<Val:13>>, <<Mask:13>>);
vlan_vid(Val, Mask) ->
    #ofp_field{name = vlan_vid,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

%vlan.vid<>none
vlan_pcp(Val) -> %3
    #ofp_field{name = vlan_pcp,
	      value = Val}.

% eth_typy=0x800|0x86dd
ip_dscp(Val) -> %6
    #ofp_field{name = ip_dscp,
	      value = Val}.
 
% eth_typy=0x800|0x86dd
ip_ecn(Val) -> %2
    #ofp_field{name = ip_ecn,
	      value = Val}.

% eth_typy=0x800|0x86dd
ip_proto(Val) -> %8
    #ofp_field{name = ip_proto,
	      value = Val}.

% eth_typy=0x800
ipv4_src(Val) when byte_size(Val)==4 ->
    #ofp_field{name = ipv4_src,
	      value = Val}.
ipv4_src(Val, Mask) when byte_size(Val)==4, byte_size(Mask)==4 ->
    #ofp_field{name = ipv4_src,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% eth_typy=0x800
ipv4_dst(Val) when byte_size(Val)==4 ->
    #ofp_field{name = ipv4_dst,
	      value = Val}.
ipv4_dst(Val, Mask) when byte_size(Val)==4, byte_size(Mask)==4 ->
    #ofp_field{name = ipv4_dst,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% ip_proto=6
tcp_src(Val) when byte_size(Val)==2 ->
    #ofp_field{name = tcp_src,
	      value = Val}.

% ip_proto=6
tcp_dst(Val) when byte_size(Val)==2 ->
    #ofp_field{name = tcp_dst,
	      value = Val}.

% ip_proto=17
udp_src(Val) when byte_size(Val)==2 ->
    #ofp_field{name = udp_src,
	      value = Val}.

% ip_proto=17
udp_dst(Val) when byte_size(Val)==2 ->
    #ofp_field{name = udp_dst,
	      value = Val}.

% ip_proto=132
sctp_src(Val) when byte_size(Val)==2 ->
    #ofp_field{name = sctp_src,
	      value = Val}.

% ip_proto=132
sctp_dst(Val) when byte_size(Val)==2 ->
    #ofp_field{name = sctp_dst,
               value = Val}.

% ip_proto=1
icmpv4_type(Val) -> %8
    #ofp_field{name = icmpv4_type,
	      value = Val}.

% ip_proto=1
icmpv4_code(Val) -> %8
    #ofp_field{name = icmpv4_code,
	      value = Val}.

% eth_type=0x806
arp_op(Val) -> % 16
    #ofp_field{name = arp_op,
	      value = Val}.

% eth_type=0x806
arp_spa(Val) -> % 32
    #ofp_field{name = arp_spa,
	      value = Val}.
% eth_type=0x806
arp_spa(Val, Mask) ->
    #ofp_field{name = arp_spa,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% eth_type=0x806
arp_tpa(Val) -> % 32
    #ofp_field{name = arp_tpa,
	      value = Val}.
arp_tpa(Val, Mask) ->
    #ofp_field{name = arp_tpa,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% eth_type=0x806
arp_sha(Val) -> % 48
    #ofp_field{name = arp_sha,
	      value = Val}.
arp_sha(Val, Mask) ->
    #ofp_field{name = arp_sha,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% eth_type=0x806
arp_tha(Val) -> % 48
    #ofp_field{name = arp_tha,
	      value = Val}.
arp_tha(Val, Mask) ->
    #ofp_field{name = arp_tha,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% eth_type=0x86dd
ipv6_src(Val) -> % 128
    #ofp_field{name = ipv6_src,
	      value = Val}.
ipv6_src(Val, Mask) ->
    #ofp_field{name = ipv6_src,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% eth_type=0x86dd
ipv6_dst(Val) -> % 128
    #ofp_field{name = ipv6_dst,
	      value = Val}.
ipv6_dst(Val, Mask) ->
    #ofp_field{name = ipv6_dst,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% eth_type=0x86dd
ipv6_label(Val) -> % 20
    #ofp_field{name = ipv6_label,
	      value = Val}.
ipv6_label(Val, Mask) ->
    #ofp_field{name = ipv6_label,
	      value = Val,
	      has_mask = true,
	      mask = Mask}.

% ip_proto=0x58
icmpv6_type(Val) -> % 8
    #ofp_field{name = icmpv6_type,
	      value = Val}.

% ip_proto=0x58
icmpv6_code(Val) -> % 8
    #ofp_field{name = icmpv6_code,
	      value = Val}.

% icmpv6_type=135|136
ipv6_nd_target(Val) -> % 128
    #ofp_field{name = ipv6_nd_target,
               value = Val}.

% icmpv6_type=135
ipv6_nd_sll(Val) -> % 48
    #ofp_field{name = ipv6_nd_sll,
	      value = Val}.

% icmpv6_type=136
ipv6_nd_tll(Val) -> % 48
    #ofp_field{name = ipv6_nd_tll,
	      value = Val}.

% eth_type=0x8847|0x8848
mpls_label(Val) -> % 20
    #ofp_field{name = mpls_label,
	      value = Val}.

% eth_type=0x8847|0x8848
mpls_tc(Val) -> % 3
    #ofp_field{name = mpls_tc,
               value = Val}.

% eth_type=0x8847|0x8848
mpls_bos(Val) ->
    #ofp_field{name = mpls_bos,
               value = Val}.

% eth_type=0x88e7
%% pbb_isid

%% tunnel_id

% eth_type=0x86dd
%% ipv6_exthdr

%%=============================================================================
%& Instructions
mk_instructions(Is) ->
    [mk_instruction(I) || I<-Is].

mk_instruction({meter, MeterId}) ->
    #ofp_instruction_meter{meter_id=MeterId};

mk_instruction({apply_actions, Actions}) when is_list(Actions) ->
    #ofp_instruction_apply_actions{actions=mk_actions(Actions)};

mk_instruction({apply_actions, Action}) ->
    #ofp_instruction_apply_actions{actions=mk_actions([Action])};

mk_instruction(clear_actions) ->
    #ofp_instruction_clear_actions{};

mk_instruction({write_actions, Actions}) when is_list(Actions) ->
    #ofp_instruction_write_actions{actions=mk_actions(Actions)};

mk_instruction({write_actions, Action}) ->
    #ofp_instruction_write_actions{actions=mk_actions([Action])};

mk_instruction({write_metadata, Metadata}) ->
    #ofp_instruction_write_metadata{metadata=Metadata};

mk_instruction({write_metadata, Metadata, Mask}) ->
    #ofp_instruction_write_metadata{metadata=Metadata,
				   metadata_mask=Mask};

mk_instruction({goto_table, Table}) ->
    #ofp_instruction_goto_table{table_id=Table};

mk_instruction({experimenter_instr, Exp, Data}) ->
    #ofp_instruction_experimenter{experimenter = Exp,
				 data = Data}.

%%=============================================================================
%& Actions

mk_actions(As) ->
    [mk_action(A) || A<-As].

mk_action({output, Port, MaxLen}) ->
    #ofp_action_output{port = Port,
		       max_len = MaxLen};

mk_action({group, Group}) ->
    #ofp_action_group{group_id = Group};

mk_action({set_queue, Queue}) ->
    #ofp_action_set_queue{queue_id = Queue};

mk_action({set_mpls_ttl, TTL}) ->
    #ofp_action_set_mpls_ttl{mpls_ttl = TTL};

mk_action(dec_mpls_ttl) ->
    #ofp_action_dec_mpls_ttl{};

mk_action({set_nw_ttl, TTL}) ->
    #ofp_action_set_nw_ttl{nw_ttl = TTL};

mk_action(dec_nw_ttl) ->
    #ofp_action_dec_nw_ttl{};

mk_action(copy_ttl_out) ->
    #ofp_action_copy_ttl_out{};

mk_action(copy_ttl_in) ->
    #ofp_action_copy_ttl_in{};

mk_action(push_vlan) ->
    #ofp_action_push_vlan{};

mk_action(pop_vlan) ->
    #ofp_action_pop_vlan{};

mk_action({push_mpls, EtherType}) ->
    #ofp_action_push_mpls{ethertype = EtherType};

mk_action({pop_mpls, EtherType}) ->
    #ofp_action_pop_mpls{ethertype = EtherType};

mk_action({push_pbb, EtherType}) ->
    #ofp_action_push_pbb{ethertype = EtherType};

mk_action(pop_pbb) ->
    #ofp_action_pop_pbb{};

mk_action({set_field, Name, Value}) ->
    #ofp_action_set_field{field = #ofp_field{name=Name,value=Value}};

mk_action({experimenter, Exp, Data}) ->
    #ofp_action_experimenter{experimenter = Exp,
			    data = Data}.
