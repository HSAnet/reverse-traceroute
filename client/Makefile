PREFIX := /usr
RESULT := result
client := augsburg-traceroute

$(client):
	$(SHELL) scripts/binarize.sh

.PHONY: deb
deb: | $(RESULT)
	$(SHELL) ../scripts/package_deb.sh

.PHONY: install
install:
	install -D $(client) $(DESTDIR)$(PREFIX)/sbin/$(client)

.PHONY: uninstall
uninstall:
	-rm -f $(DESTDIR)$(PREFIX)/sbin/$(client)

.PHONY: clean
clean:
	find . -type d -name __pycache__ -exec rm -rf "{}" \;
	rm -rf $(client) $(RESULT)

.PHONY: format
format:
	poetry run black src

$(RESULT):
	mkdir -p $@

.PHONY: distclean
distclean: clean
