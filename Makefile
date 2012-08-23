.PHONY: compile get-deps test doc clean clean-doc deep-clean

compile: rebar get-deps
	@./rebar compile

get-deps: rebar
	@./rebar get-deps

test: rebar
	@./rebar skip_deps=true eunit

doc: rebar
	@./rebar skip_deps=true doc

clean: rebar
	@./rebar clean

clean-doc:
	@rm -f doc/*.html
	@rm -f doc/*.css
	@rm -f doc/*.png
	@rm -f doc/edoc-info

deep-clean: rebar clean clean-doc
	@./rebar delete-deps
	@rm -f rebar

rebar:
	@wget -q https://github.com/downloads/basho/rebar/rebar
	@chmod u+x rebar
