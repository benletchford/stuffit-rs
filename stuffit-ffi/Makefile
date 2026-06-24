PREFIX ?= /usr/local
DESTDIR ?=
CARGO ?= cargo

TARGET_DIR := ../target/release
STATIC_LIB := $(TARGET_DIR)/libstuffit_ffi.a
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
SHARED_LIB := $(TARGET_DIR)/libstuffit_ffi.dylib
else
SHARED_LIB := $(TARGET_DIR)/libstuffit_ffi.so
endif

.PHONY: all install install-files

all:
	$(CARGO) build --release -p stuffit-ffi

install: all install-files

install-files:
	install -d "$(DESTDIR)$(PREFIX)/lib/pkgconfig" "$(DESTDIR)$(PREFIX)/include"
	install -m 644 "$(STATIC_LIB)" "$(DESTDIR)$(PREFIX)/lib/"
	install -m 755 "$(SHARED_LIB)" "$(DESTDIR)$(PREFIX)/lib/"
ifeq ($(UNAME_S),Darwin)
	install_name_tool -id "$(PREFIX)/lib/libstuffit_ffi.dylib" \
		"$(DESTDIR)$(PREFIX)/lib/libstuffit_ffi.dylib"
endif
	install -m 644 include/stuffit_ffi.h "$(DESTDIR)$(PREFIX)/include/"
	install -m 644 pkgconfig/stuffit-ffi.pc "$(DESTDIR)$(PREFIX)/lib/pkgconfig/"
