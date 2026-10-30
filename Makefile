# Install the pazuzu binary, its private library directory, the default
# config, and the systemd units.
#
#   make
#   sudo make install
#   sudo make uninstall
#   make install DESTDIR=/tmp/root PREFIX=/usr/local

PREFIX ?= /usr/local
PAZUZU_DEPS ?= /opt/pazuzu
DESTDIR ?=
BIN := build/pazuzu
LIB_NAMES := libssl libcrypto libnghttp2 libngtcp2 libngtcp2_crypto_ossl \
	libnghttp3 libbrotlienc libbrotlidec libbrotlicommon libzstd

.PHONY: all binary install uninstall

all: binary

binary: $(BIN)

$(BIN): pazuzu.asd src/*.lisp script/build-image.lisp script/build-binary.sh
	PAZUZU_DEPS=$(PAZUZU_DEPS) ./script/build-binary.sh

install: binary
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/lib/pazuzu
	install -d $(DESTDIR)/etc/pazuzu
	install -d $(DESTDIR)/etc/systemd/system
	install -d $(DESTDIR)/var/lib/pazuzu/www
	install -d $(DESTDIR)/var/log/pazuzu
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/pazuzu-bin
	printf '%s\n' \
	  '#!/bin/sh' \
	  '# Native libraries live in ../lib/pazuzu. patchelf cannot add an rpath' \
	  '# to the SBCL executable without losing its embedded core.' \
	  'here=$$(CDPATH= cd -- "$$(dirname "$$0")" && pwd)' \
	  'export LD_LIBRARY_PATH="$$here/../lib/pazuzu$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}"' \
	  'exec "$$here/pazuzu-bin" "$$@"' \
	  > $(DESTDIR)$(PREFIX)/bin/pazuzu
	chmod 0755 $(DESTDIR)$(PREFIX)/bin/pazuzu
	@set -e; \
	for name in $(LIB_NAMES); do \
	  found=0; \
	  for file in $(PAZUZU_DEPS)/lib/$$name.so*; do \
	    if [ -e "$$file" ]; then \
	      cp -a "$$file" $(DESTDIR)$(PREFIX)/lib/pazuzu/; \
	      found=1; \
	    fi; \
	  done; \
	  if [ "$$found" -ne 1 ]; then \
	    echo "missing $$name under $(PAZUZU_DEPS)/lib" >&2; \
	    exit 1; \
	  fi; \
	done
	@set -e; \
	for file in $(DESTDIR)$(PREFIX)/lib/pazuzu/*.so*; do \
	  if [ -f "$$file" ] && [ ! -L "$$file" ]; then \
	    patchelf --set-rpath '$$ORIGIN' "$$file"; \
	  fi; \
	done
	if [ ! -f $(DESTDIR)/etc/pazuzu/config.lisp ]; then \
	  install -m 0644 packaging/config.lisp $(DESTDIR)/etc/pazuzu/config.lisp; \
	fi
	sed 's|@PREFIX@|$(PREFIX)|g' packaging/pazuzu.service \
	  > $(DESTDIR)/etc/systemd/system/pazuzu.service
	install -m 0644 packaging/pazuzu.socket $(DESTDIR)/etc/systemd/system/pazuzu.socket
	install -m 0755 script/handoff.py $(DESTDIR)$(PREFIX)/lib/pazuzu/handoff.py

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/pazuzu $(DESTDIR)$(PREFIX)/bin/pazuzu-bin
	rm -f $(DESTDIR)$(PREFIX)/lib/pazuzu/handoff.py
	rm -rf $(DESTDIR)$(PREFIX)/lib/pazuzu
	rm -f $(DESTDIR)/etc/systemd/system/pazuzu.service
	rm -f $(DESTDIR)/etc/systemd/system/pazuzu.socket
	@echo "left $(DESTDIR)/etc/pazuzu and $(DESTDIR)/var/lib/pazuzu in place"
