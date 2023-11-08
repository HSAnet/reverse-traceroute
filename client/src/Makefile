PREFIX := /usr
RESULT := result
client := augsburg-traceroute

$(client):
	../scripts/binarize

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
	poetry run black .

.PHONY: distclean
distclean: clean
