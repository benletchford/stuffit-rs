PREFIX ?= /usr/local
DESTDIR ?=
CARGO ?= cargo

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CARGO_MANIFEST := $(MAKEFILE_DIR)Cargo.toml
TARGET_DIR := $(abspath $(MAKEFILE_DIR)/../target/release)
STATIC_LIB := $(TARGET_DIR)/libstuffit_ffi.a
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
SHARED_LIB := $(TARGET_DIR)/libstuffit_ffi.dylib
else
SHARED_LIB := $(TARGET_DIR)/libstuffit_ffi.so
endif

.PHONY: all install install-files

all:
	$(CARGO) build --manifest-path "$(CARGO_MANIFEST)" --release -p stuffit-ffi

install: all install-files

install-files:
	mkdir -p "$(DESTDIR)$(PREFIX)/lib/pkgconfig" "$(DESTDIR)$(PREFIX)/include"
	cp "$(STATIC_LIB)" "$(DESTDIR)$(PREFIX)/lib/libstuffit_ffi.a"
	chmod 644 "$(DESTDIR)$(PREFIX)/lib/libstuffit_ffi.a"
	cp "$(SHARED_LIB)" "$(DESTDIR)$(PREFIX)/lib/$(notdir $(SHARED_LIB))"
	chmod 755 "$(DESTDIR)$(PREFIX)/lib/$(notdir $(SHARED_LIB))"
ifeq ($(UNAME_S),Darwin)
	install_name_tool -id "$(PREFIX)/lib/libstuffit_ffi.dylib" \
		"$(DESTDIR)$(PREFIX)/lib/libstuffit_ffi.dylib"
endif
	cp "$(MAKEFILE_DIR)include/stuffit_ffi.h" "$(DESTDIR)$(PREFIX)/include/stuffit_ffi.h"
	chmod 644 "$(DESTDIR)$(PREFIX)/include/stuffit_ffi.h"
	cp "$(MAKEFILE_DIR)pkgconfig/stuffit-ffi.pc" "$(DESTDIR)$(PREFIX)/lib/pkgconfig/stuffit-ffi.pc"
	chmod 644 "$(DESTDIR)$(PREFIX)/lib/pkgconfig/stuffit-ffi.pc"
