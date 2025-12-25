# stuffit-rs

A Rust library (`stuffit`) and CLI tool for reading and writing StuffIt (.sit) archives.

> **Note:** This library targets the **classic StuffIt format** (`.sit`) used by StuffIt 1.x through 5.x.
> The newer **StuffIt X format** (`.sitx`, StuffIt 7.0+) is **not yet supported**.

> **Disclaimer:** This project is not affiliated with, endorsed by, or connected to Smith Micro Software,
> Allume Systems, or the original StuffIt developers. "StuffIt" is used here as a descriptive term
> for the file format.

StuffIt was a popular compression format on classic Macintosh systems. This crate provides
functionality to parse existing archives and create new ones, with support for the dual-fork
file system used by classic Mac OS.

## Features

- **Parse StuffIt 5.0 archives** - Read files compressed with StuffIt 5.x
- **Parse SIT! 1.x archives** - Support for the original StuffIt format
- **Create new archives** - Build StuffIt 5.0 compatible archives
- **Method 13 compression** - LZ77 with Huffman coding (native StuffIt)
- **Dual-fork support** - Preserve both data and resource forks
- **Finder metadata** - File types, creator codes, and Finder flags

## Supported Compression Methods

| Method | Name         | Read | Write |
| ------ | ------------ | ---- | ----- |
| 0      | None (store) | ✓    | ✓     |
| 13     | LZ77+Huffman | ✓    | ✓     |
| 14     | Deflate      | ✓    | ✓     |
| 15     | Arsenic/BWT  | ✓    | ✗     |

## Library Usage

```rust
use stuffit::{SitArchive, SitEntry};

// Parse an existing archive
let data = std::fs::read("archive.sit")?;
let archive = SitArchive::parse(&data)?;

for entry in &archive.entries {
    println!("{}: {} bytes (data), {} bytes (rsrc)",
        entry.name,
        entry.data_fork.len(),
        entry.resource_fork.len()
    );
}

// Create a new archive
let mut archive = SitArchive::new();

let entry = SitEntry {
    name: "hello.txt".to_string(),
    data_fork: b"Hello, World!".to_vec(),
    file_type: *b"TEXT",
    creator: *b"ttxt",
    ..Default::default()
};
archive.add_entry(entry);

// Write uncompressed
let bytes = archive.serialize()?;

// Or write with compression
let compressed = archive.serialize_compressed()?;
```

## CLI Usage

The crate includes a command-line tool (`stuffit`) for working with StuffIt archives.

### Extract an archive

```bash
stuffit extract archive.sit -o output_dir
```

### Create an archive

```bash
# Compressed (default, method 13)
stuffit archive -o output.sit file1.txt folder/

# Uncompressed
stuffit archive -o output.sit file1.txt folder/ -m 0
```

### Options

- `-v, --verbose` - Show detailed progress
- `-o, --output` - Specify output path
- `-m, --method` - Compression method (0=none, 13=compressed)

## macOS Integration

On macOS, the tool automatically handles:

- **Resource forks** - Stored in `file/..namedfork/rsrc`
- **Finder metadata** - File types, creators, and flags via `com.apple.FinderInfo`
- **Custom folder icons** - The `Icon\r` file and folder flags

## Installation

```bash
# Install from crates.io
cargo install stuffit

# Or build from source
git clone https://github.com/benletchford/stuffit-rs
cd stuffit-rs
cargo build --release
```

## Building

```bash
# Library only
cargo build --no-default-features

# With CLI tool (default)
cargo build
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## References

- [The Unarchiver](https://theunarchiver.com/) - Reference implementation
- [StuffIt File Format](https://web.archive.org/web/20030315160855/http://www.aladdinsys.com/developers/stuffit.html) - Original documentation
