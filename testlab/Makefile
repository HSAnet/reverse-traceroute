export PACKAGE_DIR := $(abspath packages)
RESULTS := results

.PHONY: test
test: $(PACKAGE_DIR)
	sudo rm -rf $(RESULTS)
	sudo mkdir $(RESULTS)
	sudo docker-compose run --build ipmininet ./test.sh

$(PACKAGE_DIR):
	$(MAKE) -C ../client
	$(MAKE) -C ../server

$(RESULTS):
	mkdir $@

.PHONY: clean
clean:
	sudo rm -rf $(RESULTS)
	$(MAKE) -C ../client clean
	$(MAKE) -C ../server clean
