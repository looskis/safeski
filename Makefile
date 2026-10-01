# safeski build/install. Requires Swift 6 (Command Line Tools are enough; no Xcode).
#
#   make build            release build into .build/release
#   make sign             ad-hoc codesign the binary + pkcs11 dylib with a stable identifier
#   make install          install to $(PREFIX) (default /usr/local; use PREFIX=$$HOME/.local)
#   make test             swift test
#   make dist             tarball in dist/
#   make clean

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
LIBDIR   ?= $(PREFIX)/lib
LIBEXEC  ?= $(PREFIX)/libexec/safeski
CONFIG   ?= release
BUILD    := .build/$(CONFIG)
BIN      := $(BUILD)/safeski
DYLIB    := $(BUILD)/libsafeski-pkcs11.dylib
IDENT    ?= dev.safeski.cli
SIGN_ID  ?= -
VERSION  := $(shell sed -n 's/.*static let string = "\(.*\)".*/\1/p' Sources/SafeskiCore/RPC/Protocol.swift)
ARCH     := $(shell uname -m)
DIST     := dist/safeski-$(VERSION)-macos-$(ARCH)

.PHONY: all build sign install uninstall test clean dist version

all: build

build:
	swift build -c $(CONFIG) 2>&1 | grep -v "ld: warning: search path" || true
	@test -x $(BIN) || { echo "build failed: $(BIN) missing"; exit 1; }

# Ad-hoc by default (SIGN_ID=-). Pass SIGN_ID="Developer ID Application: ..." to use a real identity;
# a stable identifier lets policy rules match signing_id = "dev.safeski.cli".
sign: build
	codesign --force -s "$(SIGN_ID)" --identifier $(IDENT) --options runtime $(BIN) 2>/dev/null || codesign --force -s "$(SIGN_ID)" --identifier $(IDENT) $(BIN)
	@if [ -f $(DYLIB) ]; then codesign --force -s "$(SIGN_ID)" --identifier $(IDENT).pkcs11 $(DYLIB); fi
	codesign -dv $(BIN) 2>&1 | grep -E "Identifier|Signature" || true

install: sign
	install -d $(BINDIR) $(LIBDIR)
	install -m 0755 $(BIN) $(BINDIR)/safeski
	@if [ -f $(DYLIB) ]; then install -m 0755 $(DYLIB) $(LIBDIR)/libsafeski-pkcs11.dylib && echo "installed $(LIBDIR)/libsafeski-pkcs11.dylib"; fi
	install -d $(LIBEXEC)/clients
	install -m 0644 clients/python/safeski.py clients/node/safeski.js $(LIBEXEC)/clients/
	install -m 0755 clients/shell/safeski-get $(LIBEXEC)/clients/
	@echo "installed $(BINDIR)/safeski"

uninstall:
	rm -f $(BINDIR)/safeski $(LIBDIR)/libsafeski-pkcs11.dylib
	rm -rf $(LIBEXEC)

test:
	swift test

clean:
	rm -rf .build dist

dist: sign
	rm -rf $(DIST) && mkdir -p $(DIST)/bin $(DIST)/lib $(DIST)/clients
	cp $(BIN) $(DIST)/bin/
	@if [ -f $(DYLIB) ]; then cp $(DYLIB) $(DIST)/lib/; fi
	cp -R clients/python clients/node clients/shell clients/README.md $(DIST)/clients/
	cp scripts/install.sh scripts/uninstall.sh $(DIST)/
	tar -C dist -czf $(DIST).tar.gz $(notdir $(DIST))
	@shasum -a 256 $(DIST).tar.gz

version:
	@echo $(VERSION)
