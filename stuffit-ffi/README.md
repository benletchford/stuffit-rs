# stuffit-ffi

`stuffit-ffi` exposes the `stuffit` Rust crate through a small, versioned C ABI.
It builds a shared library, optionally installs a static library when one is
produced, and ships a C header and pkg-config metadata.

## Build

```sh
cargo build --release -p stuffit-ffi
```

The resulting library is named `libstuffit_ffi`. The exact shared-library
extension depends on the platform.

## Install

```sh
cargo build --release -p stuffit-ffi
sudo make -C stuffit-ffi install-files PREFIX=/usr/local DESTDIR=/optional/staging/root
```

This installs the shared library, the static library when Cargo produced one,
and:

```text
include/stuffit_ffi.h       -> ${prefix}/include/stuffit_ffi.h
pkgconfig/stuffit-ffi.pc    -> ${prefix}/lib/pkgconfig/stuffit-ffi.pc
```

From the repository root, `make -C stuffit-ffi install` can also build and
install in one step. Use `install-files` after a separate build when installing
to a privileged prefix so Cargo does not need to run under `sudo`.

Set `INSTALL_STATIC=yes` to require the static library install, or
`INSTALL_STATIC=no` to skip it explicitly. The default, `INSTALL_STATIC=auto`,
installs the static library only when the platform toolchain produced it.

The pkg-config file is relocatable, so it derives `prefix` from its installed
location. A downstream project can then use:

```sh
cc example.c $(pkg-config --cflags --libs stuffit-ffi)
```

## Ownership and errors

- Archives and writers are opaque handles freed by their matching `*_free`
  function.
- Entry names and fork buffers are borrowed from an archive and remain valid
  until that archive is freed.
- Unsafe entry paths (absolute paths, traversal components, and backslashes)
  are rejected while parsing and writing.
- Serialized output is owned by the caller and must be released exactly once
  with `stuffit_owned_bytes_free`.
- Error state is thread-local. `stuffit_last_error_code()` gives a stable
  machine-readable category and `stuffit_last_error()` gives diagnostic text.
- No Rust panic is allowed to unwind across the C ABI boundary.
