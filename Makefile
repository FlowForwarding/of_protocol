.PHONY: all compile rel test doc clean

all: compile

compile: rebar
	./rebar get-deps compile

rel: compile
	./rebar generate -f
	./scripts/post_generate_hook

test: compile
	./rebar skip_deps=true eunit

doc:
	./rebar skip_deps=true doc

clean: rebar
	./rebar clean

rebar:
	wget -q http://cloud.github.com/downloads/basho/rebar/rebar
	chmod u+x rebar
