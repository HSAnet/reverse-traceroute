
.PHONY: all server client docker stop_docker clean
all: server client

server:
	$(MAKE) -j -C server/src

client:
	$(MAKE) -j -C client

clean:
	-$(MAKE) clean -C server/src
	-$(MAKE) clean -C client/
