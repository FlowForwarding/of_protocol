.PHONY: compile get-deps test clean deep-clean

compile: get-deps
	@./rebar compile

get-deps:
	@./rebar get-deps

test: compile
	@./rebar skip_deps=true eunit

clean:
	@./rebar clean

deep-clean: clean
	@./rebar delete-deps
