.PHONY: test server client clean
test: server client
	vagrant up
	-vagrant ssh default -c "sudo bash /reverse-traceroute/testlab/run_test.sh"
	vagrant halt

server:
	$(MAKE) -C ../server/src OUTDIR=..

client:
	cd ../client && poetry build -f wheel

clean:
	rm -f *.pcapng *.txt *.pdf
