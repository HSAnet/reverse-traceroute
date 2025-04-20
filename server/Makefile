export PACKAGE_DIR ?= package

.PHONY: deb
deb: | docs $(PACKAGE_DIR)
	../scripts/package_deb

.PHONY: docs
docs:
	find docs -type f -name '*.adoc' -exec asciidoctor -b manpage "{}" \;

.PHONY: clean
clean:
	find docs -name '*.[1-9]' -delete
	rm -rf $(PACKAGE_DIR)

$(PACKAGE_DIR):
	mkdir -p $@
