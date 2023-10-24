RESULT := result

.PHONY: deb
deb: | $(RESULT)
	$(SHELL) ../scripts/package_deb.sh

$(RESULT):
	mkdir -p $@

.PHONY: clean
clean::
	rm -rf $(RESULT)

.DEFAULT clean::
	$(MAKE) -C src $@
