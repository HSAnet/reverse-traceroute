RESULT := result

.PHONY: deb
deb: | docs $(RESULT)
	$(SHELL) ../scripts/package_deb.sh

.PHONY: docs
docs:
	find docs -type f -name '*.adoc' -exec asciidoctor -b manpage "{}" \;

.PHONY: clean
clean:
	find docs -name '*.[1-9]' -delete
	rm -rf $(RESULT)

$(RESULT):
	mkdir -p $@
