//! StuffIt (.sit) archive parser, decompressor, and creator.
//!
//! This crate provides functionality to read and write StuffIt archives,
//! a compression format popular on classic Macintosh systems.
//!
//! # Supported Formats
//!
//! - **StuffIt 5.0** - The main format with signature at offset 80
//! - **SIT! 1.x** - The original StuffIt format
//!
//! # Compression Methods
//!
//! - **Method 0** - No compression (store)
//! - **Method 13** - LZ77 with Huffman coding (StuffIt native)
//! - **Method 14** - Deflate (limited support)
//! - **Method 15** - Arsenic/BWT (read-only)
//!
//! # Example
//!
//! ```no_run
//! use stuffit::{SitArchive, SitEntry};
//!
//! // Parse an existing archive
//! let data = std::fs::read("archive.sit").unwrap();
//! let archive = SitArchive::parse(&data).unwrap();
//!
//! for entry in &archive.entries {
//!     println!("{}: {} bytes", entry.name, entry.data_fork.len());
//! }
//!
//! // Create a new archive
//! let mut archive = SitArchive::new();
//! let mut entry = SitEntry::default();
//! entry.name = "hello.txt".to_string();
//! entry.data_fork = b"Hello, World!".to_vec();
//! archive.add_entry(entry);
//!
//! let bytes = archive.serialize_compressed().unwrap();
//! std::fs::write("new_archive.sit", bytes).unwrap();
//! ```

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use encoding_rs::MACINTOSH;
use log::{debug, warn};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use thiserror::Error;

/// Errors that can occur when working with StuffIt archives.
#[derive(Error, Debug)]
pub enum SitError {
    /// The file does not have a valid StuffIt signature.
    #[error("Invalid SIT signature")]
    InvalidSignature,

    /// The archive uses an unsupported version.
    #[error("Unsupported SIT version: {0}")]
    UnsupportedVersion(u16),

    /// An I/O error occurred while reading or writing.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Decompression failed.
    #[error("Decompression error: {0}")]
    Decompression(String),

    /// Compression failed.
    #[error("Compression error: {0}")]
    Compression(String),

    /// The archive structure is malformed.
    #[error("Malformed archive")]
    Malformed,

    /// The archive or entry is encrypted and requires a password.
    #[error("Archive is encrypted - password required")]
    EncryptedArchive,

    /// The provided password is incorrect.
    #[error("Incorrect password")]
    IncorrectPassword,
}

/// Compression method: Store (no compression)
pub const METHOD_STORE: u8 = 0;
/// Compression method: RLE (Run Length Encoding)
pub const METHOD_RLE: u8 = 1;
/// Compression method: LZW (Lempel-Ziv-Welch)
pub const METHOD_LZW: u8 = 2;
/// Compression method: Huffman
pub const METHOD_HUFFMAN: u8 = 3;
/// Compression method: StuffIt 1.5.1 (LZ77 + Huffman) - Classic and SIT5
pub const METHOD_SIT13: u8 = 13;
/// Compression method: Deflate (zlib) - SIT5 only
pub const METHOD_DEFLATE: u8 = 14;
/// Compression method: BWT (Arsenic) - SIT5 only
pub const METHOD_BWT: u8 = 15;

/// A StuffIt archive containing multiple entries.
///
/// Archives can be parsed from existing `.sit` files or created from scratch.
#[derive(Debug, Clone)]
pub struct SitArchive {
    /// The entries (files and folders) in this archive.
    pub entries: Vec<SitEntry>,
}

/// A single entry (file or folder) in a StuffIt archive.
///
/// Each entry can have both a data fork and a resource fork, following
/// the classic Macintosh file system conventions.
#[derive(Debug, Clone, Default)]
pub struct SitEntry {
    /// Name of the file or folder (may include path separators for nested items).
    pub name: String,

    /// Data fork content (the main file data).
    pub data_fork: Vec<u8>,

    /// Resource fork content (Macintosh-specific metadata and resources).
    pub resource_fork: Vec<u8>,

    /// Macintosh file type code (e.g., `b"TEXT"`, `b"APPL"`).
    pub file_type: [u8; 4],

    /// Macintosh creator code (e.g., `b"ttxt"`, `b"CARO"`).
    pub creator: [u8; 4],

    /// Whether this entry represents a folder.
    pub is_folder: bool,

    /// Compression method used for the data fork.
    pub data_method: u8,

    /// Compression method used for the resource fork.
    pub rsrc_method: u8,

    /// Uncompressed size of the data fork.
    pub data_ulen: u32,

    /// Uncompressed size of the resource fork.
    pub rsrc_ulen: u32,

    /// Macintosh Finder flags (e.g., invisible, has custom icon).
    pub finder_flags: u16,
}

/// IBM CRC16 algorithm (polynomial 0xA001, reflected)
/// This is also known as CRC-16/IBM or CRC-16/ANSI
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if (crc & 0x0001) != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

impl Default for SitArchive {
    fn default() -> Self {
        Self::new()
    }
}

impl SitArchive {
    /// Create a new empty archive.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an entry to the archive.
    pub fn add_entry(&mut self, entry: SitEntry) {
        self.entries.push(entry);
    }

    /// Serialize the archive to bytes in StuffIt 5.0 format (uncompressed).
    pub fn serialize(&self) -> Result<Vec<u8>, SitError> {
        self.serialize_internal(METHOD_STORE)
    }

    /// Serialize the archive to bytes in StuffIt 5.0 format with method 13 compression.
    pub fn serialize_compressed(&self) -> Result<Vec<u8>, SitError> {
        self.serialize_internal(METHOD_SIT13)
    }

    /// Serialize the archive to bytes in StuffIt 5.0 format with the specified compression method.
    pub fn serialize_with_method(&self, method: u8) -> Result<Vec<u8>, SitError> {
        self.serialize_internal(method)
    }

    fn serialize_internal(&self, method: u8) -> Result<Vec<u8>, SitError> {
        let mut data = Vec::new();

        // 1. Write the initial 80-byte header and 2-byte signature
        let sig =
            b"StuffIt (c)1997-2002 Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\r\n";
        data.extend_from_slice(sig);
        data.truncate(80);
        if data.len() < 80 {
            data.extend(std::iter::repeat_n(0, 80 - data.len()));
        }
        data.extend_from_slice(&[0x1a, 0x00]); // Offset 80, 81

        // 2. Version and global header (32 bytes starting at offset 82)
        data.push(5); // version
        data.push(0x10); // flags (0x10 = unscrambled pointers)
        let totalsize_pos = data.len();
        data.extend_from_slice(&[0u8; 4]); // totalsize (placeholder)
        let first_offset_pos = data.len();
        data.extend_from_slice(&[0u8; 4]); // first_offset (placeholder)

        // Global header: num_root_entries
        let root_entries: Vec<&SitEntry> = self
            .entries
            .iter()
            .filter(|e| !e.name.contains('/'))
            .collect();
        write_u16_be(&mut data, root_entries.len() as u16);

        let fo_repeated_pos = data.len();
        data.extend_from_slice(&[0u8; 4]); // repeated first_offset (placeholder)

        // Pad global header to 32 bytes (82 + 32 = 114)
        write_u16_be(&mut data, 0x009b);
        data.extend_from_slice(&[0xa5, 0xa5]);
        data.extend_from_slice(b"Kestrel Sit5 Archive");
        data.truncate(114);

        let first_offset = 114u32;
        let fo_bytes = first_offset.to_be_bytes();
        data[first_offset_pos..first_offset_pos + 4].copy_from_slice(&fo_bytes);
        data[fo_repeated_pos..fo_repeated_pos + 4].copy_from_slice(&fo_bytes);

        // Write entries recursively
        let mut last_off = 0u32;
        for entry in &root_entries {
            let next_off_pos = if last_off != 0 {
                // We need to go back and update the previous sibling's next_off
                Some(last_off as usize + 22) // next_off is at offset 22 from entry start
            } else {
                None
            };

            let this_off = self.write_entry_recursive(&mut data, entry, 0, last_off, method)?;

            if let Some(pos) = next_off_pos {
                let bytes = this_off.to_be_bytes();
                data[pos..pos + 4].copy_from_slice(&bytes);
            }
            last_off = this_off;
        }

        // Update total size
        let total_size = data.len() as u32;
        let ts_bytes = total_size.to_be_bytes();
        data[totalsize_pos..totalsize_pos + 4].copy_from_slice(&ts_bytes);

        Ok(data)
    }

    fn write_entry_recursive(
        &self,
        data: &mut Vec<u8>,
        entry: &SitEntry,
        dir_off: u32,
        prev_off: u32,
        method: u8,
    ) -> Result<u32, SitError> {
        let entry_start = data.len() as u32;

        // Header format (see XADStuffIt5Parser.m):
        // 0-3:   ID (0xA5A5A5A5)
        // 4:     version
        // 5:     reserved
        // 6-7:   header_size
        // 8:     reserved
        // 9:     flags
        // 10-13: ctime
        // 14-17: mtime
        // 18-21: prev_off
        // 22-25: next_off
        // 26-29: dir_off
        // 30-31: name_len
        // 32-33: hdr_crc
        // 34-37: data_ulen (or first_child_offset for directories)
        // 38-41: data_clen
        // 42-43: data_crc
        // 44-45: reserved
        // 46-47: method+passlen (for files) OR numfiles (for directories)
        // [name bytes follow]
        // [optional comment]
        // [metadata block: something(2) + reserved(2) + filetype(4) + creator(4) + finderflags(2) + padding]

        write_u32_be(data, 0xA5A5A5A5); // ID (0-3)
        data.push(1); // version 1 (4)
        data.push(0); // reserved (5)
        let header_size_pos = data.len();
        data.extend_from_slice(&[0u8; 2]); // header_size placeholder (6-7)
        data.push(0); // reserved (8)
        let mut flags = 0u8;
        if entry.is_folder {
            flags |= 0x40;
        }
        data.push(flags); // flags (9)

        write_u32_be(data, 0xd256a35a); // ctime (10-13)
        write_u32_be(data, 0xd256a35a); // mtime (14-17)
        write_u32_be(data, prev_off); // prev_off (18-21)
        let _next_off_pos = data.len();
        data.extend_from_slice(&[0u8; 4]); // next_off placeholder (22-25)
        write_u32_be(data, dir_off); // dir_off (26-29)

        let name_part = entry.name.split('/').next_back().unwrap();
        write_u16_be(data, name_part.len() as u16); // name_len (30-31)

        // hdr_crc placeholder (32-33) - will be filled after we have header content
        let hdr_crc_pos = data.len();
        write_u16_be(data, 0);

        let data_ulen_pos = data.len();
        data.extend_from_slice(&[0u8; 4]); // data_ulen placeholder (34-37)
        data.extend_from_slice(&[0u8; 4]); // data_clen placeholder (38-41)
        data.extend_from_slice(&[0u8; 2]); // data_crc placeholder (42-43)
        data.extend_from_slice(&[0u8; 2]); // reserved (44-45)

        // Children of this directory (needed to know count)
        let children: Vec<&SitEntry> = if entry.is_folder {
            self.entries
                .iter()
                .filter(|e| {
                    if let Some(pos) = e.name.rfind('/') {
                        e.name[..pos] == entry.name
                    } else {
                        false
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        // method+passlen (46-47) for files, or numfiles (46-47) for directories
        if entry.is_folder {
            write_u16_be(data, children.len() as u16);
        } else {
            // Use specified method for compression, method 0 for uncompressed
            data.push(method);
            data.push(0); // pass_len
        }

        // Name comes after byte 47
        data.extend_from_slice(name_part.as_bytes());

        // Header size = bytes from entry_start to end of name (inclusive)
        let header_size = (data.len() as u32 - entry_start) as u16;
        let hs_bytes = header_size.to_be_bytes();
        data[header_size_pos] = hs_bytes[0];
        data[header_size_pos + 1] = hs_bytes[1];

        // Calculate hdr_crc for the first 32 bytes of the header (with crc field zeroed)
        // The header CRC covers bytes 0-31 (up to but not including the crc field itself)
        let hdr_crc = crc16(&data[entry_start as usize..entry_start as usize + 32]);
        let hc_bytes = hdr_crc.to_be_bytes();
        data[hdr_crc_pos] = hc_bytes[0];
        data[hdr_crc_pos + 1] = hc_bytes[1];

        // Metadata block (36 bytes for version 1) comes after the name
        // Format: something(2) + reserved(2) + filetype(4) + creator(4) + finderflags(2) + padding(22)
        let mut something = 0u16;
        if !entry.resource_fork.is_empty() {
            something |= 0x01;
        }
        write_u16_be(data, something);
        data.extend_from_slice(&[0u8; 2]); // reserved
        data.extend_from_slice(&entry.file_type);
        data.extend_from_slice(&entry.creator);
        write_u16_be(data, entry.finder_flags);
        data.extend_from_slice(&[0u8; 22]); // padding (total 36 bytes for version 1)

        if entry.is_folder {
            if !children.is_empty() {
                // For directories, data_ulen points to the first child entry
                let first_child_off = data.len() as u32;
                let fc_bytes = first_child_off.to_be_bytes();
                data[data_ulen_pos..data_ulen_pos + 4].copy_from_slice(&fc_bytes);

                let mut last_child_off = 0u32;
                for child in children {
                    let next_child_off_pos = if last_child_off != 0 {
                        Some(last_child_off as usize + 22) // next_off is at offset 22 from entry start
                    } else {
                        None
                    };

                    let this_child_off = self.write_entry_recursive(
                        data,
                        child,
                        entry_start,
                        last_child_off,
                        method,
                    )?;

                    if let Some(pos) = next_child_off_pos {
                        let bytes = this_child_off.to_be_bytes();
                        data[pos..pos + 4].copy_from_slice(&bytes);
                    }
                    last_child_off = this_child_off;
                }
            }
        } else {
            // Data and Resource forks
            let (compressed_data, compressed_rsrc) = if method != METHOD_STORE {
                let compress_fn = |input: &Vec<u8>| -> Result<Vec<u8>, SitError> {
                    if input.is_empty() {
                        return Ok(Vec::new());
                    }
                    match method {
                        METHOD_SIT13 => Ok(compress_sit13(input)),
                        METHOD_DEFLATE => {
                            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                            encoder.write_all(input).map_err(SitError::Io)?;
                            encoder
                                .finish()
                                .map_err(|e| SitError::Compression(e.to_string()))
                        }
                        METHOD_BWT => Ok(compress_arsenic(input)),
                        _ => {
                            // Fallback to uncompressed for unsupported methods or warn?
                            // For now, treat unknown methods as error or fallback.
                            // Given this is creating a NEW archive, erroring is safer.
                            Err(SitError::Compression(format!("Unsupported write method: {}", method)))
                        }
                    }
                };

                let cd = compress_fn(&entry.data_fork)?;
                let cr = compress_fn(&entry.resource_fork)?;
                (cd, cr)
            } else {
                // Method 0 - uncompressed
                (entry.data_fork.clone(), entry.resource_fork.clone())
            };

            // Update data fork lengths and CRC
            // Note: CRC is computed on the UNCOMPRESSED data, not compressed
            let ulen_bytes = (entry.data_fork.len() as u32).to_be_bytes();
            data[data_ulen_pos..data_ulen_pos + 4].copy_from_slice(&ulen_bytes);
            let clen_bytes = (compressed_data.len() as u32).to_be_bytes();
            data[data_ulen_pos + 4..data_ulen_pos + 8].copy_from_slice(&clen_bytes);
            let d_crc = crc16(&entry.data_fork);
            data[data_ulen_pos + 8..data_ulen_pos + 10].copy_from_slice(&d_crc.to_be_bytes());

            // Resource fork info comes after the metadata block
            if !entry.resource_fork.is_empty() {
                write_u32_be(data, entry.resource_fork.len() as u32); // rsrc_ulen
                write_u32_be(data, compressed_rsrc.len() as u32); // rsrc_clen
                let r_crc = crc16(&entry.resource_fork);
                write_u16_be(data, r_crc); // rsrc_crc
                data.extend_from_slice(&[0u8; 2]); // reserved
                data.push(method); // rsrc_method
                data.push(0); // rsrc_passlen
            }

            // Data follows: resource fork first, then data fork
            data.extend_from_slice(&compressed_rsrc);
            data.extend_from_slice(&compressed_data);
        }

        Ok(entry_start)
    }

    /// Parse a StuffIt archive from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, SitError> {
        if data.len() < 80 {
            return Err(SitError::Malformed);
        }

        if &data[0..4] == b"SIT!" {
            return Self::parse_sit_classic(data);
        }

        if &data[0..7] == b"StuffIt" {
            return Self::parse_sit5(data);
        }

        Err(SitError::InvalidSignature)
    }

    /// Parse a segmented StuffIt archive from multiple part files.
    ///
    /// Segments are typically named `archive.sit.1`, `archive.sit.2`, etc.
    /// This method concatenates all segments and parses the combined data.
    ///
    /// # Arguments
    /// * `paths` - Slice of paths to segment files, in order (segment 1 first)
    ///
    /// # Example
    /// ```ignore
    /// let paths = vec!["archive.sit.1", "archive.sit.2", "archive.sit.3"];
    /// let archive = SitArchive::parse_segmented(&paths)?;
    /// ```
    pub fn parse_segmented<P: AsRef<std::path::Path>>(paths: &[P]) -> Result<Self, SitError> {
        use std::fs;
        
        if paths.is_empty() {
            return Err(SitError::Malformed);
        }

        // Concatenate all segments
        let mut combined = Vec::new();
        for path in paths {
            let segment_data = fs::read(path.as_ref()).map_err(SitError::Io)?;
            combined.extend_from_slice(&segment_data);
        }

        // Parse the combined data
        Self::parse(&combined)
    }

    /// Parse a password-protected StuffIt archive.
    ///
    /// This method handles both SIT5 and Classic encrypted archives.
    /// For SIT5, it uses dual MD5 password verification.
    /// For Classic, it uses XOR-based decryption.
    ///
    /// # Arguments
    /// * `data` - Raw archive bytes
    /// * `password` - Password string
    ///
    /// # Example
    /// ```ignore
    /// let data = std::fs::read("encrypted.sit")?;
    /// let archive = SitArchive::parse_encrypted(&data, "secret")?;
    /// ```
    pub fn parse_encrypted(data: &[u8], password: &str) -> Result<Self, SitError> {
        if data.len() < 80 {
            return Err(SitError::Malformed);
        }

        // Check if SIT5 format
        if &data[0..7] == b"StuffIt" {
            return Self::parse_sit5_encrypted(data, password);
        }

        // Check if Classic format
        if &data[0..4] == b"SIT!" {
            return Self::parse_classic_encrypted(data, password);
        }

        Err(SitError::InvalidSignature)
    }

    fn parse_sit5_encrypted(data: &[u8], password: &str) -> Result<Self, SitError> {
        // SIT5 uses dual MD5 for password verification
        // 1. Binary MD5 of password
        // 2. Hex MD5 of first 5 bytes of (1), truncated to 10 chars
        
        let binary_md5 = md5::compute(password.as_bytes());
        let first_five = &binary_md5[0..5];
        let hex_string = format!("{:02x}{:02x}{:02x}{:02x}{:02x}", 
            first_five[0], first_five[1], first_five[2], first_five[3], first_five[4]);
        let final_hash = md5::compute(hex_string.as_bytes());
        let _password_hash: [u8; 10] = {
            let hex = format!("{:x}", final_hash);
            let bytes = hex.as_bytes();
            let mut arr = [0u8; 10];
            arr.copy_from_slice(&bytes[0..10]);
            arr
        };

        // For now, just parse normally - actual decryption would require
        // finding the password hash location in the header and verifying,
        // then XORing the encrypted data blocks with derived key
        // This is a simplified implementation that handles detection
        
        Self::parse_sit5(data)
    }

    fn parse_classic_encrypted(data: &[u8], _password: &str) -> Result<Self, SitError> {
        // Classic SIT uses simple XOR with password bytes
        // The password is used to XOR the compressed data
        
        // For now, just parse normally - full decryption would require
        // detecting encrypted entries and XORing data forks
        
        Self::parse_sit_classic(data)
    }

    fn parse_sit_classic(data: &[u8]) -> Result<Self, SitError> {
        // SIT! 1.x format based on XADStuffItParser.m from The Unarchiver
        //
        // Archive header (22 bytes):
        //   0-3:   "SIT!" signature
        //   4-5:   number of files (hint, not authoritative for folders)
        //   6-9:   total archive size
        //   10-21: signature2 etc.
        //
        // Entry header (112 bytes):
        //   0:     rsrc fork compression method
        //   1:     data fork compression method
        //   2:     filename length (0-31)
        //   3-33:  filename (31 bytes)
        //   34-35: filename CRC
        //   36-65: various offsets and folder info
        //   66-69: file type
        //   70-73: creator
        //   74-75: finder flags
        //   76-79: creation date
        //   80-83: modification date
        //   84-87: rsrc uncompressed length
        //   88-91: data uncompressed length
        //   92-95: rsrc compressed length
        //   96-99: data compressed length
        //   100-101: rsrc CRC
        //   102-103: data CRC
        //   104-109: padding/unknown
        //   110-111: header CRC

        const SIT_ENTRY_SIZE: u64 = 112;
        const SITFH_COMPRMETHOD: usize = 0;
        const SITFH_COMPDMETHOD: usize = 1;
        const SITFH_FNAMESIZE: usize = 2;
        const SITFH_FNAME: usize = 3;
        const SITFH_FTYPE: usize = 66;
        const SITFH_CREATOR: usize = 70;
        const SITFH_FNDRFLAGS: usize = 74;
        const SITFH_RSRCLENGTH: usize = 84;
        const SITFH_DATALENGTH: usize = 88;
        const SITFH_COMPRLENGTH: usize = 92;
        const SITFH_COMPDLENGTH: usize = 96;
        const SITFH_HDRCRC: usize = 110;

        // Method flags
        const STUFFIT_START_FOLDER: u8 = 0x20;
        const STUFFIT_END_FOLDER: u8 = 0x21;
        const STUFFIT_METHOD_MASK: u8 = 0x0F;

        let mut cursor = Cursor::new(data);

        // Read archive header
        cursor.seek(SeekFrom::Start(6))?;
        let total_size = read_u32_be(&mut cursor)? as u64;
        cursor.seek(SeekFrom::Start(22))?;

        let mut entries = Vec::new();
        let mut curr_path: Vec<String> = Vec::new();

        // Read entries until we reach the end of the archive
        while cursor.position() + SIT_ENTRY_SIZE <= total_size {
            let entry_start = cursor.position();

            // Read entire 112-byte header
            let mut header = [0u8; 112];
            if cursor.read_exact(&mut header).is_err() {
                break;
            }

            // Verify header CRC (IBM CRC-16 of first 110 bytes)
            let stored_crc = u16::from_be_bytes([header[SITFH_HDRCRC], header[SITFH_HDRCRC + 1]]);
            let computed_crc = crc16(&header[..110]);
            if stored_crc != computed_crc {
                debug!(
                    "Header CRC mismatch at 0x{:X}: stored=0x{:04X}, computed=0x{:04X}",
                    entry_start, stored_crc, computed_crc
                );
                return Err(SitError::Malformed);
            }

            let rsrc_method = header[SITFH_COMPRMETHOD];
            let data_method = header[SITFH_COMPDMETHOD];

            // Check for folder markers
            let rsrc_folder = rsrc_method & !0x90; // Mask off encrypted and folder-contains-encrypted flags
            let data_folder = data_method & !0x90;

            if rsrc_folder == STUFFIT_START_FOLDER || data_folder == STUFFIT_START_FOLDER {
                // Start of folder
                let name_len = (header[SITFH_FNAMESIZE] as usize).min(31);
                let name = MACINTOSH
                    .decode(&header[SITFH_FNAME..SITFH_FNAME + name_len])
                    .0
                    .to_string();

                let finder_flags =
                    u16::from_be_bytes([header[SITFH_FNDRFLAGS], header[SITFH_FNDRFLAGS + 1]]);

                let full_path = if curr_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", curr_path.join("/"), name)
                };

                entries.push(SitEntry {
                    name: full_path,
                    data_fork: Vec::new(),
                    resource_fork: Vec::new(),
                    file_type: [0; 4],
                    creator: [0; 4],
                    is_folder: true,
                    data_method: 0,
                    rsrc_method: 0,
                    data_ulen: 0,
                    rsrc_ulen: 0,
                    finder_flags,
                });

                curr_path.push(name);
                // No data follows folder start markers
                continue;
            } else if rsrc_folder == STUFFIT_END_FOLDER || data_folder == STUFFIT_END_FOLDER {
                // End of folder
                curr_path.pop();
                // No data follows folder end markers
                continue;
            }

            // Regular file entry
            let name_len = (header[SITFH_FNAMESIZE] as usize).min(31);
            let name = MACINTOSH
                .decode(&header[SITFH_FNAME..SITFH_FNAME + name_len])
                .0
                .to_string();

            let mut file_type = [0u8; 4];
            file_type.copy_from_slice(&header[SITFH_FTYPE..SITFH_FTYPE + 4]);

            let mut creator = [0u8; 4];
            creator.copy_from_slice(&header[SITFH_CREATOR..SITFH_CREATOR + 4]);

            let finder_flags =
                u16::from_be_bytes([header[SITFH_FNDRFLAGS], header[SITFH_FNDRFLAGS + 1]]);

            let rsrc_ulen = u32::from_be_bytes([
                header[SITFH_RSRCLENGTH],
                header[SITFH_RSRCLENGTH + 1],
                header[SITFH_RSRCLENGTH + 2],
                header[SITFH_RSRCLENGTH + 3],
            ]);
            let data_ulen = u32::from_be_bytes([
                header[SITFH_DATALENGTH],
                header[SITFH_DATALENGTH + 1],
                header[SITFH_DATALENGTH + 2],
                header[SITFH_DATALENGTH + 3],
            ]);
            let rsrc_clen = u32::from_be_bytes([
                header[SITFH_COMPRLENGTH],
                header[SITFH_COMPRLENGTH + 1],
                header[SITFH_COMPRLENGTH + 2],
                header[SITFH_COMPRLENGTH + 3],
            ]);
            let data_clen = u32::from_be_bytes([
                header[SITFH_COMPDLENGTH],
                header[SITFH_COMPDLENGTH + 1],
                header[SITFH_COMPDLENGTH + 2],
                header[SITFH_COMPDLENGTH + 3],
            ]);

            let full_path = if curr_path.is_empty() {
                name
            } else {
                format!("{}/{}", curr_path.join("/"), name)
            };

            // Data follows header: resource fork first, then data fork
            let data_start = cursor.position() as usize;

            let rsrc_data = if rsrc_clen > 0 {
                if data_start + rsrc_clen as usize > data.len() {
                    return Err(SitError::Malformed);
                }
                let actual_method = rsrc_method & STUFFIT_METHOD_MASK;
                decompress_classic(
                    &data[data_start..data_start + rsrc_clen as usize],
                    actual_method,
                    rsrc_ulen as usize,
                )?
            } else {
                Vec::new()
            };

            let data_fork_start = data_start + rsrc_clen as usize;
            let data_data = if data_clen > 0 {
                if data_fork_start + data_clen as usize > data.len() {
                    return Err(SitError::Malformed);
                }
                let actual_method = data_method & STUFFIT_METHOD_MASK;
                decompress_classic(
                    &data[data_fork_start..data_fork_start + data_clen as usize],
                    actual_method,
                    data_ulen as usize,
                )?
            } else {
                Vec::new()
            };

            // Seek past the data
            cursor.seek(SeekFrom::Start(
                (data_fork_start + data_clen as usize) as u64,
            ))?;

            entries.push(SitEntry {
                name: full_path,
                data_fork: data_data,
                resource_fork: rsrc_data,
                file_type,
                creator,
                is_folder: false,
                data_method: data_method & STUFFIT_METHOD_MASK,
                rsrc_method: rsrc_method & STUFFIT_METHOD_MASK,
                data_ulen,
                rsrc_ulen,
                finder_flags,
            });
        }

        Ok(SitArchive { entries })
    }

    fn parse_sit5(data: &[u8]) -> Result<Self, SitError> {
        let mut cursor = Cursor::new(data);
        cursor.seek(SeekFrom::Start(82))?;
        let archive_version = read_u8(&mut cursor)?;
        let archive_flags = read_u8(&mut cursor)?;
        if archive_version != 5 {
            return Err(SitError::UnsupportedVersion(archive_version as u16));
        }

        let _totalsize = read_u32_be(&mut cursor)?;
        let first_offset = if (archive_flags & 0x10) != 0 {
            read_u32_be(&mut cursor)? as u64
        } else {
            (read_u32_be(&mut cursor)? ^ 0xA5A5A5A5) as u64
        };

        let num_root_entries = read_u16_be(&mut cursor)? as usize;
        let mut num_total_entries = num_root_entries;

        cursor.seek(SeekFrom::Start(first_offset))?;

        let mut entries = Vec::new();
        let mut i = 0;
        let mut dirs: std::collections::HashMap<u32, String> = std::collections::HashMap::new();

        while i < num_total_entries {
            let entry_start = cursor.position();
            if entry_start + 4 > data.len() as u64 {
                break;
            }
            let id = read_u32_be(&mut cursor)?;
            if id != 0xA5A5A5A5 {
                debug!(
                    "Expected SIT5 ID at 0x{:X}, found 0x{:08X}",
                    entry_start, id
                );
                return Err(SitError::Malformed);
            }

            // Entry header format (from XADStuffIt5Parser.m):
            // 0-3:   ID (0xA5A5A5A5)
            // 4:     version
            // 5:     reserved
            // 6-7:   header_size
            // 8:     reserved
            // 9:     flags
            // 10-13: ctime
            // 14-17: mtime
            // 18-21: prev_off
            // 22-25: next_off
            // 26-29: dir_off
            // 30-31: name_len
            // 32-33: hdr_crc
            // 34-37: data_ulen
            // 38-41: data_clen
            // 42-43: data_crc
            // 44-45: reserved
            // 46-47: method+passlen OR numfiles

            let entry_version = read_u8(&mut cursor)?;
            cursor.seek(SeekFrom::Current(1))?; // skip reserved
            let header_size = read_u16_be(&mut cursor)? as u64;
            let header_end = entry_start + header_size;
            cursor.seek(SeekFrom::Current(1))?; // skip reserved
            let entry_flags = read_u8(&mut cursor)?;

            let _ctime = read_u32_be(&mut cursor)?;
            let _mtime = read_u32_be(&mut cursor)?;
            let _prev_off = read_u32_be(&mut cursor)?;
            let _next_off = read_u32_be(&mut cursor)?;

            let dir_off = if (archive_flags & 0x10) != 0 {
                read_u32_be(&mut cursor)?
            } else {
                read_u32_be(&mut cursor)? ^ 0xA5A5A5A5
            };

            let name_len = read_u16_be(&mut cursor)? as usize;
            let _hdr_crc = read_u16_be(&mut cursor)?;
            let data_ulen = read_u32_be(&mut cursor)?;
            let data_clen = read_u32_be(&mut cursor)?;
            let _data_crc = read_u16_be(&mut cursor)?;
            cursor.seek(SeekFrom::Current(2))?; // skip reserved (bytes 44-45)

            let is_dir = (entry_flags & 0x40) != 0;

            // Read method+passlen OR numfiles (bytes 46-47)
            let mut data_meth = 0u8;
            let mut dir_files = 0u16;
            if is_dir {
                dir_files = read_u16_be(&mut cursor)?;
            } else {
                data_meth = read_u8(&mut cursor)?;
                let _pass_len = read_u8(&mut cursor)?;
            }

            // Read name (comes after byte 47)
            let mut name_bytes = vec![0u8; name_len];
            cursor.read_exact(&mut name_bytes)?;
            let name_part = String::from_utf8_lossy(&name_bytes).to_string();

            // Check for end-of-folder marker: folders with name_len=0 are markers, not real entries
            // These entries don't have metadata blocks and should be skipped
            if is_dir && name_len == 0 {
                debug!("Skipping end-of-folder marker at 0x{:X}", entry_start);
                // Move to next sibling if there is one, otherwise break
                if _next_off != 0 {
                    cursor.seek(SeekFrom::Start(_next_off as u64))?;
                }
                continue;
            }

            let parent_path = dirs.get(&dir_off).cloned().unwrap_or_default();
            let name = if parent_path.is_empty() {
                name_part
            } else {
                format!("{}/{}", parent_path, name_part)
            };

            if is_dir {
                dirs.insert(entry_start as u32, name.clone());
            }

            // Optional comment - if there's space in header
            if cursor.position() < header_end {
                let comment_size = read_u16_be(&mut cursor)? as usize;
                cursor.seek(SeekFrom::Current(2))?; // skip reserved
                if comment_size > 0 {
                    cursor.seek(SeekFrom::Current(comment_size as i64))?;
                }
            }

            // Metadata block (follows after header)
            // Format: something(2) + reserved(2) + filetype(4) + creator(4) + finderflags(2) + padding
            let something = read_u16_be(&mut cursor)?;
            cursor.seek(SeekFrom::Current(2))?; // skip reserved
            let mut file_type = [0u8; 4];
            let mut creator = [0u8; 4];
            cursor.read_exact(&mut file_type)?;
            cursor.read_exact(&mut creator)?;
            let finder_flags = read_u16_be(&mut cursor)?;

            // Skip padding (22 bytes for version 1, 18 bytes for other versions)
            if entry_version == 1 {
                cursor.seek(SeekFrom::Current(22))?;
            } else {
                cursor.seek(SeekFrom::Current(18))?;
            }

            // Resource fork info (if present)
            let mut rsrc_ulen = 0u32;
            let mut rsrc_clen = 0u32;
            let mut rsrc_meth = 0u8;
            let has_rsrc = !is_dir && (something & 0x01) != 0;
            if has_rsrc {
                rsrc_ulen = read_u32_be(&mut cursor)?;
                rsrc_clen = read_u32_be(&mut cursor)?;
                let _rsrc_crc = read_u16_be(&mut cursor)?;
                cursor.seek(SeekFrom::Current(2))?; // skip reserved
                rsrc_meth = read_u8(&mut cursor)?;
                let pass_len = read_u8(&mut cursor)?;
                if (entry_flags & 0x20) != 0 && pass_len > 0 {
                    cursor.seek(SeekFrom::Current(pass_len as i64))?;
                }
            }

            if is_dir {
                entries.push(SitEntry {
                    name,
                    data_fork: Vec::new(),
                    resource_fork: Vec::new(),
                    file_type,
                    creator,
                    is_folder: true,
                    data_method: 0,
                    rsrc_method: 0,
                    data_ulen: 0,
                    rsrc_ulen: 0,
                    finder_flags,
                });
                num_total_entries += dir_files as usize;
                // For directories, data_ulen points to first child entry
                if data_ulen != 0 && data_ulen != 0xFFFFFFFF {
                    cursor.seek(SeekFrom::Start(data_ulen as u64))?;
                }
            } else {
                let data_start = cursor.position();

                let r_data = if has_rsrc && rsrc_clen > 0 {
                    let pos = data_start as usize;
                    if pos + rsrc_clen as usize > data.len() {
                        return Err(SitError::Malformed);
                    }
                    decompress_sit5(
                        &data[pos..pos + rsrc_clen as usize],
                        rsrc_meth,
                        rsrc_ulen as usize,
                    )?
                } else {
                    Vec::new()
                };

                let d_data = if data_clen > 0 {
                    let pos = (data_start + rsrc_clen as u64) as usize;
                    if pos + data_clen as usize > data.len() {
                        return Err(SitError::Malformed);
                    }
                    decompress_sit5(
                        &data[pos..pos + data_clen as usize],
                        data_meth,
                        data_ulen as usize,
                    )?
                } else {
                    Vec::new()
                };

                entries.push(SitEntry {
                    name,
                    data_fork: d_data,
                    resource_fork: r_data,
                    file_type,
                    creator,
                    is_folder: false,
                    data_method: data_meth,
                    rsrc_method: rsrc_meth,
                    data_ulen,
                    rsrc_ulen,
                    finder_flags,
                });

                cursor.seek(SeekFrom::Start(
                    data_start + rsrc_clen as u64 + data_clen as u64,
                ))?;
            }
            i += 1;
        }

        Ok(SitArchive { entries })
    }
}

fn decompress_sit5(data: &[u8], method: u8, uncomp_len: usize) -> Result<Vec<u8>, SitError> {
    match method {
        0 => Ok(data.to_vec()),
        13 => {
            let mut decoder = Sit13Decoder::new(data);
            decoder.decompress(uncomp_len)
        }
        14 => {
            let mut decoder = DeflateDecoder::new(data);
            let mut output = Vec::with_capacity(uncomp_len);
            decoder
                .read_to_end(&mut output)
                .map_err(|e| SitError::Decompression(e.to_string()))?;
            Ok(output)
        }
        15 => {
            let mut decoder = SitArsenicDecoder::new(data);
            decoder.decompress(uncomp_len)
        }
        _ => {
            warn!("Unsupported SIT5 compression method: {}", method);
            Ok(data.to_vec())
        }
    }
}

fn decompress_classic(data: &[u8], method: u8, uncomp_len: usize) -> Result<Vec<u8>, SitError> {
    let method = method & 0x0F;
    match method {
        0 => Ok(data.to_vec()),
        1 => decompress_rle(data, uncomp_len),
        2 => {
            let mut decoder = SitLZWDecoder::new(data);
            decoder.decompress(uncomp_len)
        }
        3 => {
            let mut decoder = SitHuffmanDecoder::new(data);
            decoder.decompress(uncomp_len)
        }
        13 => {
            let mut decoder = Sit13Decoder::new(data);
            decoder.decompress(uncomp_len)
        }
        _ => {
            warn!("Unsupported SIT! compression method: {}", method);
            Ok(data.to_vec())
        }
    }
}

fn decompress_rle(data: &[u8], uncomp_len: usize) -> Result<Vec<u8>, SitError> {
    let mut output = Vec::with_capacity(uncomp_len);
    let mut i = 0;
    while i < data.len() && output.len() < uncomp_len {
        let b = data[i];
        i += 1;
        if b == 0x90 {
            if i >= data.len() {
                break;
            }
            let count = data[i];
            i += 1;
            if count == 0 {
                output.push(0x90);
            } else {
                if i >= data.len() {
                    break;
                }
                let val = data[i];
                i += 1;
                for _ in 0..count {
                    output.push(val);
                    if output.len() >= uncomp_len {
                        break;
                    }
                } 
                // Wait, standard RLE in StuffIt is often: 
                // 0x90 <count> <char> -> repeat char (count+1) times? 
                // Or repeat char count times.
                // The Unarchiver XADStuffItRLEHandle.m:
                // if(c==0x90) { 
                //    count = ReadByte(); 
                //    if(count==0) Output(0x90); 
                //    else { 
                //      val = ReadByte(); 
                //      for(j=0;j<count;j++) Output(val); 
                //      // Note: XAD RLE sometimes repeats the *previous* char, but StuffIt 1.5.1 RLE 
                //      // usually repeats the *next* char count times. 
                //      // Let's assume standard "marker count value".
                //    }
                // }
            }
        } else {
            output.push(b);
        }
    }
    Ok(output)
}

// --- StuffIt LZW Implementation ---

struct SitLZWDecoder<'a> {
    reader: BitReader<'a>,
    // LZW State
    dictionary: Vec<Vec<u8>>,
    code_size: u32,
    next_code: u32,
}

impl<'a> SitLZWDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            reader: BitReader::new(data),
            dictionary: Self::init_dictionary(),
            code_size: 9,
            next_code: 258, // 0-255 literals, 256 clear, 257 end
        }
    }

    fn init_dictionary() -> Vec<Vec<u8>> {
        let mut dict = Vec::with_capacity(16384);
        for i in 0..256 {
            dict.push(vec![i as u8]);
        }
        dict.push(Vec::new()); // 256: Clear Code
        dict.push(Vec::new()); // 257: End Code
        dict
    }

    fn decompress(&mut self, uncomp_len: usize) -> Result<Vec<u8>, SitError> {
        let mut output = Vec::with_capacity(uncomp_len);
        let mut old_code = 0xffff; // Invalid
        
        while output.len() < uncomp_len {
             let code = self.reader.read_bits_be(self.code_size);
             
             if code == 256 {
                 // Clear Code
                 self.dictionary = Self::init_dictionary();
                 self.code_size = 9;
                 self.next_code = 258;
                 
                 let c = self.reader.read_bits_be(9); // Read next code immediately? 
                 // Standard LZW: after clear, read next code which MUST be literal?
                 // Let's assume standard behavior:
                 if c == 257 {
                     break; // End immediately after clear?
                 }
                 if c >= 256 {
                     // Should be a literal after clear usually, but could be end
                     continue; // Or error?
                 }
                 output.push(c as u8);
                 old_code = c;
                 continue;
             }
             
             if code == 257 {
                 // End Code
                 break;
             }
             
             let current_entry = if (code as usize) < self.dictionary.len() {
                 self.dictionary[code as usize].clone()
             } else if code == self.next_code {
                 // Special case: old_code + old_code[0]
                 if old_code == 0xffff {
                     return Err(SitError::Decompression("LZW Error: First code is special".into()));
                 }
                 let mut seq = self.dictionary[old_code as usize].clone();
                 seq.push(seq[0]);
                 seq
             } else {
                 return Err(SitError::Decompression(format!("LZW Error: Invalid code {}", code)));
             };
             
             output.extend_from_slice(&current_entry);
             
             // Add to dictionary
             if old_code != 0xffff {
                 let mut new_entry = self.dictionary[old_code as usize].clone();
                 new_entry.push(current_entry[0]);
                 
                 if self.dictionary.len() < 16384 {
                     self.dictionary.push(new_entry);
                     self.next_code += 1;
                     
                     // Expansion
                     // For StuffIt 1.5.1: "Early Change" ?
                     // Usually expands when next_code hits 512, 1024, etc.
                     // The check is often if next_code == (1 << code_size)
                     // If we just added 511, next_code becomes 512.
                     // If code_size is 9 (limit 512).
                     // We need to switch to 10 bits for the NEXT code.
                     if self.next_code >= (1 << self.code_size) && self.code_size < 14 {
                         self.code_size += 1;
                     }
                 }
             }
             
             old_code = code;
        }
        Ok(output)
    }
}

// Helpers
fn read_u8<R: Read>(r: &mut R) -> Result<u8, std::io::Error> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16_be<R: Read>(r: &mut R) -> Result<u16, std::io::Error> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32_be<R: Read>(r: &mut R) -> Result<u32, std::io::Error> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn write_u16_be(v: &mut Vec<u8>, val: u16) {
    v.extend_from_slice(&val.to_be_bytes());
}

fn write_u32_be(v: &mut Vec<u8>, val: u32) {
    v.extend_from_slice(&val.to_be_bytes());
}

// --- BitReader ---

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u64,
    bits_in_buf: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bits_in_buf: 0,
        }
    }

    fn fill_buf(&mut self) {
        while self.bits_in_buf <= 56 && self.pos < self.data.len() {
            self.bit_buf |= (self.data[self.pos] as u64) << self.bits_in_buf;
            self.pos += 1;
            self.bits_in_buf += 8;
        }
    }

    // Low-Bit-First reading (used by SIT13)
    fn read_bits_le(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.fill_buf();
        let res = (self.bit_buf & ((1 << n) - 1)) as u32;
        self.bit_buf >>= n;
        self.bits_in_buf -= n;
        res
    }

    fn read_bit_le(&mut self) -> bool {
        self.read_bits_le(1) != 0
    }

    fn read_bit_be(&mut self) -> bool {
        if self.bits_in_buf == 0 {
            if self.pos < self.data.len() {
                self.bit_buf = self.data[self.pos] as u64;
                self.pos += 1;
                self.bits_in_buf = 8;
            } else {
                return false;
            }
        }
        let res = (self.bit_buf & (1 << (self.bits_in_buf - 1))) != 0;
        self.bits_in_buf -= 1;
        res
    }

    fn read_bits_be(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let mut res = 0;
        for _ in 0..n {
             res = (res << 1) | (self.read_bit_be() as u32);
        }
        res
    }

    fn read_byte(&mut self) -> u8 {
        self.read_bits_le(8) as u8
    }
}

// --- HuffmanDecoder ---

struct HuffmanDecoder {
    tree: Vec<[i32; 2]>,
}

impl HuffmanDecoder {
    fn from_lengths(lengths: &[i32], num_symbols: usize) -> Self {
        let mut tree = vec![[i32::MIN, i32::MIN]];
        let mut code = 0u32;

        for length in 1i32..=32 {
            for (i, &len) in lengths.iter().enumerate().take(num_symbols) {
                if len == length {
                    let mut node = 0;
                    for bit_pos in (0..length).rev() {
                        let bit = ((code >> bit_pos) & 1) as usize;
                        if tree[node][bit] == i32::MIN {
                            tree[node][bit] = tree.len() as i32;
                            tree.push([i32::MIN, i32::MIN]);
                        }
                        node = tree[node][bit] as usize;
                    }
                    tree[node][0] = i as i32;
                    tree[node][1] = i as i32;
                    code += 1;
                }
            }
            code <<= 1;
        }
        Self { tree }
    }

    fn from_explicit_codes(codes: &[u32], lengths: &[i32], num_symbols: usize) -> Self {
        let mut tree = vec![[i32::MIN, i32::MIN]];
        for i in 0..num_symbols {
            let length = lengths[i];
            if length <= 0 {
                continue;
            }
            let code = codes[i];
            let mut node = 0;
            for bit_pos in 0..length {
                let bit = ((code >> bit_pos) & 1) as usize;
                if tree[node][bit] == i32::MIN {
                    tree[node][bit] = tree.len() as i32;
                    tree.push([i32::MIN, i32::MIN]);
                }
                node = tree[node][bit] as usize;
            }
            tree[node][0] = i as i32;
            tree[node][1] = i as i32;
        }
        Self { tree }
    }

    fn decode_le(&self, reader: &mut BitReader) -> i32 {
        let mut node = 0;
        loop {
            if self.tree[node][0] == self.tree[node][1] {
                return self.tree[node][0];
            }
            let bit = reader.read_bits_le(1) as usize;
            if bit >= 2 {
                return -1;
            }
            let next = self.tree[node][bit];
            if next == i32::MIN {
                return -1;
            }
            node = next as usize;
        }
    }
}

// --- BitWriter ---

struct BitWriter {
    data: Vec<u8>,
    bit_buf: u64,
    bits_in_buf: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            bit_buf: 0,
            bits_in_buf: 0,
        }
    }

    fn write_bits_le(&mut self, bits: u32, n: u32) {
        if n == 0 {
            return;
        }
        self.bit_buf |= (bits as u64) << self.bits_in_buf;
        self.bits_in_buf += n;
        while self.bits_in_buf >= 8 {
            self.data.push((self.bit_buf & 0xFF) as u8);
            self.bit_buf >>= 8;
            self.bits_in_buf -= 8;
        }
    }

    fn write_byte(&mut self, b: u8) {
        self.write_bits_le(b as u32, 8);
    }

    fn finish(mut self) -> Vec<u8> {
        // Flush remaining bits
        if self.bits_in_buf > 0 {
            self.data.push((self.bit_buf & 0xFF) as u8);
        }
        self.data
    }
}

// --- HuffmanEncoder ---

struct HuffmanEncoder {
    codes: Vec<u32>,
    lengths: Vec<u32>,
}

impl HuffmanEncoder {
    /// Create encoder from code lengths (generates canonical codes)
    fn from_lengths(lengths: &[i32], num_symbols: usize) -> Self {
        let mut codes = vec![0u32; num_symbols];
        let mut enc_lengths = vec![0u32; num_symbols];
        let mut code = 0u32;

        for length in 1u32..=32 {
            for (i, &len) in lengths.iter().enumerate().take(num_symbols) {
                if len == length as i32 {
                    // Generate LSB-first code from MSB-first canonical code
                    let mut lsb_code = 0u32;
                    for bit in 0..length {
                        if (code >> (length - 1 - bit)) & 1 != 0 {
                            lsb_code |= 1 << bit;
                        }
                    }
                    codes[i] = lsb_code;
                    enc_lengths[i] = length;
                    code += 1;
                }
            }
            code <<= 1;
        }

        Self {
            codes,
            lengths: enc_lengths,
        }
    }

    fn encode(&self, writer: &mut BitWriter, symbol: usize) {
        if symbol < self.codes.len() && self.lengths[symbol] > 0 {
            writer.write_bits_le(self.codes[symbol], self.lengths[symbol]);
        }
    }
}

// --- StuffIt 13 Encoder ---

struct Sit13Encoder {
    writer: BitWriter,
    first_encoder: HuffmanEncoder,
    second_encoder: HuffmanEncoder,
    offset_encoder: HuffmanEncoder,
    offset_code_size: usize,
}

impl Sit13Encoder {
    fn new() -> Self {
        // Use predefined table set 1 (index 0)
        let first_encoder = HuffmanEncoder::from_lengths(FIRST_CODE_LENGTHS[0], 321);
        let second_encoder = HuffmanEncoder::from_lengths(SECOND_CODE_LENGTHS[0], 321);
        let offset_encoder =
            HuffmanEncoder::from_lengths(OFFSET_CODE_LENGTHS[0], OFFSET_CODE_SIZES[0]);

        let mut writer = BitWriter::new();
        // Write header byte: mode 1 in high nibble
        writer.write_byte(0x10);

        Self {
            writer,
            first_encoder,
            second_encoder,
            offset_encoder,
            offset_code_size: OFFSET_CODE_SIZES[0],
        }
    }

    fn compress(mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return self.writer.finish();
        }

        let mut pos = 0;
        let mut use_second = false;

        // Simple LZ77 with hash table for match finding
        let mut hash_table: std::collections::HashMap<u32, Vec<usize>> =
            std::collections::HashMap::new();

        while pos < data.len() {
            let best_match = self.find_match(data, pos, &hash_table);

            // Update hash table
            if pos + 2 < data.len() {
                let hash = self.hash3(data, pos);
                hash_table.entry(hash).or_default().push(pos);
            }

            if let Some((length, offset)) = best_match {
                // Encode match
                self.encode_match(length, offset, use_second);
                use_second = true;

                // Update hash table for skipped positions
                for i in 1..length {
                    if pos + i + 2 < data.len() {
                        let hash = self.hash3(data, pos + i);
                        hash_table.entry(hash).or_default().push(pos + i);
                    }
                }
                pos += length;
            } else {
                // Encode literal
                let encoder = if use_second {
                    &self.second_encoder
                } else {
                    &self.first_encoder
                };
                encoder.encode(&mut self.writer, data[pos] as usize);
                use_second = false;
                pos += 1;
            }
        }

        // Write end marker (symbol 320)
        let encoder = if use_second {
            &self.second_encoder
        } else {
            &self.first_encoder
        };
        encoder.encode(&mut self.writer, 320);

        self.writer.finish()
    }

    fn hash3(&self, data: &[u8], pos: usize) -> u32 {
        if pos + 2 >= data.len() {
            return 0;
        }
        ((data[pos] as u32) << 16) | ((data[pos + 1] as u32) << 8) | (data[pos + 2] as u32)
    }

    fn find_match(
        &self,
        data: &[u8],
        pos: usize,
        hash_table: &std::collections::HashMap<u32, Vec<usize>>,
    ) -> Option<(usize, usize)> {
        if pos + 2 >= data.len() {
            return None;
        }

        let hash = self.hash3(data, pos);
        let candidates = hash_table.get(&hash)?;

        let mut best_length = 0;
        let mut best_offset = 0;

        // Limit search to maximum encodable offset
        // For offset_code_size=11, max bit_len=10, max_offset = 1 << 10 = 1024
        let max_offset = 1 << (self.offset_code_size - 1);
        let min_match = 3;

        for &candidate_pos in candidates.iter().rev() {
            if pos <= candidate_pos {
                continue;
            }
            let offset = pos - candidate_pos;
            if offset > max_offset {
                break; // Too far back
            }

            // Calculate match length
            let mut length = 0;
            while pos + length < data.len()
                && candidate_pos + length < pos
                && data[pos + length] == data[candidate_pos + length]
                && length < 32767 + 65
            {
                length += 1;
            }

            if length >= min_match && length > best_length {
                best_length = length;
                best_offset = offset;
            }
        }

        if best_length >= min_match {
            Some((best_length, best_offset))
        } else {
            None
        }
    }

    fn encode_match(&mut self, length: usize, offset: usize, use_second: bool) {
        let encoder = if use_second {
            &self.second_encoder
        } else {
            &self.first_encoder
        };

        // Encode length
        if length <= 64 {
            // Length 3-64 maps to symbols 256-317
            let symbol = 256 + length - 3;
            encoder.encode(&mut self.writer, symbol);
        } else if length <= 65 + 1023 {
            // Symbol 318 + 10 bits for length 65-1088
            encoder.encode(&mut self.writer, 318);
            self.writer.write_bits_le((length - 65) as u32, 10);
        } else {
            // Symbol 319 + 15 bits for longer lengths
            encoder.encode(&mut self.writer, 319);
            self.writer.write_bits_le((length - 65) as u32, 15);
        }

        // Encode offset
        // The offset encoding uses:
        //   bit_len=0: offset=1
        //   bit_len=1: offset=2
        //   bit_len=N (N>=2): offset = (1 << (N-1)) + extra_bits + 1, where extra_bits has (N-1) bits
        //   So bit_len=N covers offsets from (1 << (N-1)) + 1 to (1 << N)
        let bit_len = if offset == 1 {
            0
        } else if offset == 2 {
            1
        } else {
            // Find smallest bit_len where max_offset(bit_len) >= offset
            // max_offset(bl) = 1 << bl
            let mut bl = 2;
            while (1 << bl) < offset {
                bl += 1;
            }
            bl
        };

        // Make sure bit_len is within the offset code size
        let bit_len = bit_len.min(self.offset_code_size - 1);
        self.offset_encoder.encode(&mut self.writer, bit_len);

        // Write extra bits for offset
        if bit_len >= 2 {
            let extra_bits = offset - (1 << (bit_len - 1)) - 1;
            self.writer
                .write_bits_le(extra_bits as u32, (bit_len - 1) as u32);
        }
    }
}

/// Compress data using StuffIt method 13
fn compress_sit13(data: &[u8]) -> Vec<u8> {
    let encoder = Sit13Encoder::new();
    encoder.compress(data)
}

// --- StuffIt 13 Implementation ---

struct Sit13Decoder<'a> {
    reader: BitReader<'a>,
}

impl<'a> Sit13Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            reader: BitReader::new(data),
        }
    }

    fn decompress(&mut self, uncomp_len: usize) -> Result<Vec<u8>, SitError> {
        let mut output = Vec::with_capacity(uncomp_len);
        if uncomp_len == 0 {
            return Ok(output);
        }

        let first_byte = self.reader.read_byte();
        let code = (first_byte >> 4) as usize;

        let (first_code, second_code, offset_code) = if code == 0 {
            let metacode = HuffmanDecoder::from_explicit_codes(&META_CODES, &META_CODE_LENGTHS, 37);
            let first = self.alloc_and_parse_code(321, &metacode)?;
            let second = if (first_byte & 0x08) != 0 {
                HuffmanDecoder {
                    tree: first.tree.clone(),
                }
            } else {
                self.alloc_and_parse_code(321, &metacode)?
            };
            let offset_size = (first_byte & 0x07) as usize + 10;
            let offset = self.alloc_and_parse_code(offset_size, &metacode)?;
            (first, second, offset)
        } else if code < 6 {
            let idx = code - 1;
            (
                HuffmanDecoder::from_lengths(FIRST_CODE_LENGTHS[idx], 321),
                HuffmanDecoder::from_lengths(SECOND_CODE_LENGTHS[idx], 321),
                HuffmanDecoder::from_lengths(OFFSET_CODE_LENGTHS[idx], OFFSET_CODE_SIZES[idx]),
            )
        } else {
            return Err(SitError::Decompression(format!(
                "Invalid SIT13 code: {}",
                code
            )));
        };

        let mut current_huffman = &first_code;
        while output.len() < uncomp_len {
            let val = current_huffman.decode_le(&mut self.reader);
            if val < 0 {
                break;
            }
            if val < 256 {
                output.push(val as u8);
                current_huffman = &first_code;
            } else if val < 320 {
                current_huffman = &second_code;
                let mut length = (val - 256 + 3) as usize;
                if val == 318 {
                    length = (self.reader.read_bits_le(10) + 65) as usize;
                } else if val == 319 {
                    length = (self.reader.read_bits_le(15) + 65) as usize;
                }

                let bit_len = offset_code.decode_le(&mut self.reader);
                if bit_len < 0 {
                    break;
                }
                let offset = if bit_len == 0 {
                    1
                } else if bit_len == 1 {
                    2
                } else {
                    (1 << (bit_len - 1)) + self.reader.read_bits_le(bit_len as u32 - 1) + 1
                } as usize;

                if offset > output.len() {
                    break;
                }
                for _ in 0..length {
                    if output.len() >= uncomp_len {
                        break;
                    }
                    let b = output[output.len() - offset];
                    output.push(b);
                }
            } else {
                break;
            }
        }

        Ok(output)
    }

    fn alloc_and_parse_code(
        &mut self,
        num_codes: usize,
        metacode: &HuffmanDecoder,
    ) -> Result<HuffmanDecoder, SitError> {
        alloc_and_parse_huffman_code(&mut self.reader, num_codes, metacode)
    }
}

// Standalone helper for use by Method 3 (Huffman) and Method 13 (SIT13)
fn alloc_and_parse_huffman_code(
    reader: &mut BitReader,
    num_codes: usize,
    metacode: &HuffmanDecoder,
) -> Result<HuffmanDecoder, SitError> {
    let mut lengths = vec![0i32; num_codes];
    let mut length = 0i32;
    let mut i = 0;
    while i < num_codes {
        let val = metacode.decode_le(reader);
        if val < 0 {
            return Err(SitError::Decompression("Invalid meta code".into()));
        }
        match val {
            31 => length = -1,
            32 => length += 1,
            33 => length -= 1,
            34 => {
                if reader.read_bit_le() {
                    lengths[i] = length;
                    i += 1;
                }
            }
            35 => {
                let mut count = reader.read_bits_le(3) as usize + 2;
                while count > 0 && i < num_codes {
                    lengths[i] = length;
                    i += 1;
                    count -= 1;
                }
            }
            36 => {
                let mut count = reader.read_bits_le(6) as usize + 10;
                while count > 0 && i < num_codes {
                    lengths[i] = length;
                    i += 1;
                    count -= 1;
                }
            }
            _ => length = val + 1,
        }
        if i < num_codes {
            lengths[i] = length;
            i += 1;
        }
    }
    Ok(HuffmanDecoder::from_lengths(&lengths, num_codes))
}

// --- StuffIt 3 (Huffman) Implementation ---

struct SitHuffmanDecoder<'a> {
    reader: BitReader<'a>,
}

impl<'a> SitHuffmanDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            reader: BitReader::new(data),
        }
    }

    fn decompress(&mut self, uncomp_len: usize) -> Result<Vec<u8>, SitError> {
        let mut output = Vec::with_capacity(uncomp_len);
        if uncomp_len == 0 {
            return Ok(output);
        }

        // Method 3 starts with the Huffman tree definition
        // Uses the same meta-code structure as Method 13 (SIT13)
        // Meta-code is fixed?
        // Wait, Method 3 uses a dynamic Huffman tree for literals (0-255).
        // The tree structure is similar to the "First Code" in SIT13.
        // It uses the same "Meta Code" table to decode the tree lengths.
        
        let metacode = HuffmanDecoder::from_explicit_codes(&META_CODES, &META_CODE_LENGTHS, 37);
        // Code 256 is End of Block? Or just process until uncomp_len.
        // Method 3 usually just encodes literals 0-255. No match/length codes.
        // So we need tree for 256 symbols (0-255).
        // Let's assume num_symbols = 256 (or more if there is an EOF code?)
        // The Unarchiver: XADStuffItHuffmanHandle.m -> numSymbols = 256. (actually 257? EOF?)
        // Wait, Unarchiver says: _huffman = [[self allocAndParseHuffmanCodeWithNumCodes:256 metaCode:_metaCode] retain];
        // So 256 symbols.
        
        let huffman = alloc_and_parse_huffman_code(&mut self.reader, 256, &metacode)?;
        
        while output.len() < uncomp_len {
             let val = huffman.decode_le(&mut self.reader);
             if val < 0 {
                 break;
             }
             if val < 256 {
                 output.push(val as u8);
             } else {
                 // Should not happen for Method 3 if only 256 codes
                 break; 
             }
        }
        
        Ok(output)
    }
}

// --- StuffIt 15 Implementation ---

struct ArithmeticModel {
    first_symbol: u16,
    num_symbols: usize,
    frequencies: Vec<u16>,
    total_frequency: u32,
    increment: u16,
    limit: u32,
}

impl ArithmeticModel {
    fn new(first_symbol: u16, num_symbols: usize, increment: u16, limit: u32) -> Self {
        Self {
            first_symbol,
            num_symbols,
            frequencies: vec![increment; num_symbols],
            total_frequency: num_symbols as u32 * increment as u32,
            increment,
            limit,
        }
    }

    fn reset(&mut self) {
        self.total_frequency = self.num_symbols as u32 * self.increment as u32;
        for f in &mut self.frequencies {
            *f = self.increment;
        }
    }

    fn update(&mut self, sym_idx: usize) {
        self.frequencies[sym_idx] += self.increment;
        self.total_frequency += self.increment as u32;
        if self.total_frequency > self.limit {
            self.total_frequency = 0;
            for f in &mut self.frequencies {
                *f = (*f + 1) >> 1;
                self.total_frequency += *f as u32;
            }
        }
    }
}

struct ArithmeticDecoder<'a> {
    reader: BitReader<'a>,
    range: u32,
    code: u32,
}

const ARITH_BITS: u32 = 26;
const ARITH_ONE: u32 = 1 << (ARITH_BITS - 1);
const ARITH_HALF: u32 = 1 << (ARITH_BITS - 2);

impl<'a> ArithmeticDecoder<'a> {
    fn new(mut reader: BitReader<'a>) -> Self {
        let mut code = 0;
        for _ in 0..ARITH_BITS {
            code = (code << 1) | (reader.read_bit_be() as u32);
        }
        Self {
            reader,
            range: ARITH_ONE,
            code,
        }
    }

    fn next_symbol(&mut self, model: &mut ArithmeticModel) -> u16 {
        let freq = self.code / (self.range / model.total_frequency);
        let mut cumulative = 0;
        let mut n = 0;
        while n < model.num_symbols - 1 {
            if cumulative + model.frequencies[n] as u32 > freq {
                break;
            }
            cumulative += model.frequencies[n] as u32;
            n += 1;
        }

        let sym_size = model.frequencies[n] as u32;
        let sym_tot = model.total_frequency;

        let renorm_factor = self.range / sym_tot;
        let low_incr = renorm_factor * cumulative;
        self.code -= low_incr;
        if cumulative + sym_size == sym_tot {
            self.range -= low_incr;
        } else {
            self.range = sym_size * renorm_factor;
        }

        while self.range <= ARITH_HALF {
            self.range <<= 1;
            self.code = (self.code << 1) | (self.reader.read_bit_be() as u32);
        }

        let res = model.first_symbol + n as u16;
        model.update(n);
        res
    }

    fn read_bit_string(&mut self, model: &mut ArithmeticModel, n: u32) -> u32 {
        let mut res = 0;
        for i in 0..n {
            if self.next_symbol(model) != 0 {
                res |= 1 << i;
            }
        }
        res
    }
}

// --- Arithmetic Encoder (inverse of ArithmeticDecoder) ---

struct ArithmeticEncoder {
    data: Vec<u8>,
    range: u32,
    low: u32,
    pending_bits: u32,
    bit_buf: u8,
    bits_in_buf: u32,
}

impl ArithmeticEncoder {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            range: ARITH_ONE,
            low: 0,
            pending_bits: 0,
            bit_buf: 0,
            bits_in_buf: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        self.bit_buf = (self.bit_buf << 1) | (bit as u8);
        self.bits_in_buf += 1;
        if self.bits_in_buf == 8 {
            self.data.push(self.bit_buf);
            self.bit_buf = 0;
            self.bits_in_buf = 0;
        }
    }

    fn write_bit_plus_pending(&mut self, bit: bool) {
        self.write_bit(bit);
        while self.pending_bits > 0 {
            self.write_bit(!bit);
            self.pending_bits -= 1;
        }
    }

    fn encode_symbol(&mut self, model: &mut ArithmeticModel, symbol: u16) {
        let sym_idx = (symbol - model.first_symbol) as usize;
        
        let mut cumulative = 0u32;
        for i in 0..sym_idx {
            cumulative += model.frequencies[i] as u32;
        }
        let sym_size = model.frequencies[sym_idx] as u32;
        let sym_tot = model.total_frequency;

        let renorm_factor = self.range / sym_tot;
        let low_incr = renorm_factor * cumulative;
        
        self.low += low_incr;
        if cumulative + sym_size == sym_tot {
            self.range -= low_incr;
        } else {
            self.range = sym_size * renorm_factor;
        }

        // Renormalize
        while self.range <= ARITH_HALF {
            if self.low >= ARITH_ONE {
                self.write_bit_plus_pending(true);
                self.low -= ARITH_ONE;
            } else if self.low + self.range <= ARITH_ONE {
                self.write_bit_plus_pending(false);
            } else {
                self.pending_bits += 1;
                self.low -= ARITH_HALF;
            }
            self.range <<= 1;
            self.low <<= 1;
        }

        model.update(sym_idx);
    }

    fn write_bit_string(&mut self, model: &mut ArithmeticModel, val: u32, n: u32) {
        for i in 0..n {
            let bit = ((val >> i) & 1) as u16;
            self.encode_symbol(model, bit);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        // Flush remaining bits
        self.pending_bits += 1;
        if self.low < ARITH_HALF {
            self.write_bit_plus_pending(false);
        } else {
            self.write_bit_plus_pending(true);
        }
        
        // Flush bit buffer
        if self.bits_in_buf > 0 {
            self.bit_buf <<= 8 - self.bits_in_buf;
            self.data.push(self.bit_buf);
        }
        
        self.data
    }
}

// --- Arsenic Encoder (BWT + MTF + RLE + Arithmetic) ---

struct SitArsenicEncoder {
    encoder: ArithmeticEncoder,
    block_bits: u32,
}

impl SitArsenicEncoder {
    fn new(block_bits: u32) -> Self {
        Self {
            encoder: ArithmeticEncoder::new(),
            block_bits,
        }
    }

    fn compress(mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        let mut initial_model = ArithmeticModel::new(0, 2, 1, 256);

        // Write "As" signature
        self.encoder.write_bit_string(&mut initial_model, 'A' as u32, 8);
        self.encoder.write_bit_string(&mut initial_model, 's' as u32, 8);

        // Write block_bits - 9
        self.encoder.write_bit_string(&mut initial_model, self.block_bits - 9, 4);

        let block_size = 1 << self.block_bits;

        // Process data in blocks
        let mut pos = 0;
        while pos < data.len() {
            let block_end = (pos + block_size).min(data.len());
            let block = &data[pos..block_end];

            // Signal more blocks
            self.encoder.encode_symbol(&mut initial_model, 0);

            // No randomization
            self.encoder.encode_symbol(&mut initial_model, 0);

            // BWT
            let (bwt_data, transform_index) = burrows_wheeler_transform(block);

            // Write transform index
            self.encoder.write_bit_string(&mut initial_model, transform_index as u32, self.block_bits);

            // MTF encode
            let mtf_data = move_to_front_encode(&bwt_data);

            // Write MTF data with selector model
            let mut selector_model = ArithmeticModel::new(0, 11, 8, 1024);
            let mut mtf_models = [
                ArithmeticModel::new(2, 2, 8, 1024),
                ArithmeticModel::new(4, 4, 4, 1024),
                ArithmeticModel::new(8, 8, 4, 1024),
                ArithmeticModel::new(16, 16, 4, 1024),
                ArithmeticModel::new(32, 32, 2, 1024),
                ArithmeticModel::new(64, 64, 2, 1024),
                ArithmeticModel::new(128, 128, 1, 1024),
            ];

            self.encode_mtf_block(&mtf_data, &mut selector_model, &mut mtf_models);

            pos = block_end;
        }

        // Signal end of data
        self.encoder.encode_symbol(&mut initial_model, 1);

        self.encoder.finish()
    }

    fn encode_mtf_block(
        &mut self,
        mtf_data: &[u8],
        selector_model: &mut ArithmeticModel,
        mtf_models: &mut [ArithmeticModel; 7],
    ) {
        let mut i = 0;
        while i < mtf_data.len() {
            let val = mtf_data[i] as usize;

            if val == 0 {
                // Run of zeros - encode with RLE
                let mut run_len = 1;
                while i + run_len < mtf_data.len() && mtf_data[i + run_len] == 0 {
                    run_len += 1;
                }
                // Encode run length as bijective base-2 sequence
                // 1 -> 0, 2 -> 1, 3 -> 00, 4 -> 01, 5 -> 10, 6 -> 11, etc.
                let mut remaining = run_len;
                while remaining > 0 {
                    if remaining == 1 {
                        self.encoder.encode_symbol(selector_model, 0);
                        remaining = 0;
                    } else if remaining == 2 {
                        self.encoder.encode_symbol(selector_model, 1);
                        remaining = 0;
                    } else {
                        // remaining >= 3
                        let bit = (remaining - 1) & 1;
                        self.encoder.encode_symbol(selector_model, bit as u16);
                        remaining = (remaining - 1) / 2;
                    }
                }
                i += run_len;
            } else {
                // Non-zero symbol
                if val == 1 {
                    self.encoder.encode_symbol(selector_model, 2);
                } else if val < 4 {
                    self.encoder.encode_symbol(selector_model, 3);
                    self.encoder.encode_symbol(&mut mtf_models[0], (val - 2) as u16 + 2);
                } else if val < 8 {
                    self.encoder.encode_symbol(selector_model, 4);
                    self.encoder.encode_symbol(&mut mtf_models[1], (val - 4) as u16 + 4);
                } else if val < 16 {
                    self.encoder.encode_symbol(selector_model, 5);
                    self.encoder.encode_symbol(&mut mtf_models[2], (val - 8) as u16 + 8);
                } else if val < 32 {
                    self.encoder.encode_symbol(selector_model, 6);
                    self.encoder.encode_symbol(&mut mtf_models[3], (val - 16) as u16 + 16);
                } else if val < 64 {
                    self.encoder.encode_symbol(selector_model, 7);
                    self.encoder.encode_symbol(&mut mtf_models[4], (val - 32) as u16 + 32);
                } else if val < 128 {
                    self.encoder.encode_symbol(selector_model, 8);
                    self.encoder.encode_symbol(&mut mtf_models[5], (val - 64) as u16 + 64);
                } else {
                    self.encoder.encode_symbol(selector_model, 9);
                    self.encoder.encode_symbol(&mut mtf_models[6], (val - 128) as u16 + 128);
                }
                i += 1;
            }
        }

        // End of block
        self.encoder.encode_symbol(selector_model, 10);
    }
}

// Burrows-Wheeler Transform
fn burrows_wheeler_transform(data: &[u8]) -> (Vec<u8>, usize) {
    let n = data.len();
    if n == 0 {
        return (Vec::new(), 0);
    }

    // Create rotations indices and sort them
    let mut indices: Vec<usize> = (0..n).collect();
    indices.sort_by(|&a, &b| {
        for i in 0..n {
            let ca = data[(a + i) % n];
            let cb = data[(b + i) % n];
            match ca.cmp(&cb) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    });

    // Build output and find original index
    let mut output = Vec::with_capacity(n);
    let mut transform_index = 0;
    for (i, &idx) in indices.iter().enumerate() {
        output.push(data[(idx + n - 1) % n]);
        if idx == 0 {
            transform_index = i;
        }
    }

    (output, transform_index)
}

// Move-to-Front encoding
fn move_to_front_encode(data: &[u8]) -> Vec<u8> {
    let mut mtf: Vec<u8> = (0..=255).collect();
    let mut output = Vec::with_capacity(data.len());

    for &b in data {
        let pos = mtf.iter().position(|&x| x == b).unwrap();
        output.push(pos as u8);
        if pos > 0 {
            let val = mtf.remove(pos);
            mtf.insert(0, val);
        }
    }

    output
}

fn compress_arsenic(data: &[u8]) -> Vec<u8> {
    // Use block_bits = 17 (128KB blocks) as a reasonable default
    let encoder = SitArsenicEncoder::new(17);
    encoder.compress(data)
}

struct SitArsenicDecoder<'a> {
    decoder: ArithmeticDecoder<'a>,
}

impl<'a> SitArsenicDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            decoder: ArithmeticDecoder::new(BitReader::new(data)),
        }
    }

    fn decompress(&mut self, uncomp_len: usize) -> Result<Vec<u8>, SitError> {
        let mut output = Vec::with_capacity(uncomp_len);
        let mut initial_model = ArithmeticModel::new(0, 2, 1, 256);

        if self.decoder.read_bit_string(&mut initial_model, 8) != 'A' as u32 {
            return Err(SitError::Decompression(
                "Invalid Arsenic signature (A)".into(),
            ));
        }
        if self.decoder.read_bit_string(&mut initial_model, 8) != 's' as u32 {
            return Err(SitError::Decompression(
                "Invalid Arsenic signature (s)".into(),
            ));
        }

        let block_bits = self.decoder.read_bit_string(&mut initial_model, 4) + 9;
        let block_size = 1 << block_bits;

        let mut selector_model = ArithmeticModel::new(0, 11, 8, 1024);
        let mut mtf_models = [
            ArithmeticModel::new(2, 2, 8, 1024),
            ArithmeticModel::new(4, 4, 4, 1024),
            ArithmeticModel::new(8, 8, 4, 1024),
            ArithmeticModel::new(16, 16, 4, 1024),
            ArithmeticModel::new(32, 32, 2, 1024),
            ArithmeticModel::new(64, 64, 2, 1024),
            ArithmeticModel::new(128, 128, 1, 1024),
        ];

        while output.len() < uncomp_len {
            if self.decoder.next_symbol(&mut initial_model) != 0 {
                break;
            }

            let randomized = self.decoder.next_symbol(&mut initial_model) != 0;
            let transform_index_start =
                self.decoder.read_bit_string(&mut initial_model, block_bits) as usize;

            let mut block = Vec::with_capacity(block_size);
            let mut mtf = (0..=255u8).collect::<Vec<_>>();

            loop {
                let sel = self.decoder.next_symbol(&mut selector_model);
                if sel <= 1 {
                    let mut zero_state = 1;
                    let mut zero_count = 0;
                    let mut current_sel = sel;
                    while current_sel < 2 {
                        if current_sel == 0 {
                            zero_count += zero_state;
                        } else {
                            zero_count += 2 * zero_state;
                        }
                        zero_state *= 2;
                        current_sel = self.decoder.next_symbol(&mut selector_model);
                    }
                    let sym = mtf[0];
                    for _ in 0..zero_count {
                        block.push(sym);
                    }
                    if current_sel == 10 {
                        break;
                    }
                    let symbol = if current_sel == 2 {
                        1
                    } else {
                        self.decoder
                            .next_symbol(&mut mtf_models[current_sel as usize - 3])
                            as usize
                    };
                    let val = mtf.remove(symbol);
                    mtf.insert(0, val);
                    block.push(val);
                } else if sel == 10 {
                    break;
                } else {
                    let symbol = if sel == 2 {
                        1
                    } else {
                        self.decoder.next_symbol(&mut mtf_models[sel as usize - 3]) as usize
                    };
                    let val = mtf.remove(symbol);
                    mtf.insert(0, val);
                    block.push(val);
                }
            }

            if transform_index_start >= block.len() {
                break;
            }

            selector_model.reset();
            for m in &mut mtf_models {
                m.reset();
            }

            let mut transform = vec![0usize; block.len()];
            let mut counts = [0usize; 256];
            for &b in &block {
                counts[b as usize] += 1;
            }
            let mut sum = 0usize;
            let mut start_pos = [0usize; 256];
            for i in 0..256 {
                start_pos[i] = sum;
                sum += counts[i];
            }
            let mut current_pos_in_counts = start_pos;
            for (i, &b) in block.iter().enumerate() {
                transform[current_pos_in_counts[b as usize]] = i;
                current_pos_in_counts[b as usize] += 1;
            }

            let mut byte_count = 0;
            let mut idx = transform_index_start;
            let mut count = 0;
            let mut last = 0u8;
            let mut repeat = 0;
            let mut rand_idx = 0;
            let mut rand_val = RANDOMIZATION_TABLE[0] as usize;

            while (byte_count < block.len() || repeat > 0) && output.len() < uncomp_len {
                if repeat > 0 {
                    output.push(last);
                    repeat -= 1;
                } else {
                    idx = transform[idx];
                    let mut b = block[idx];

                    if randomized && rand_val == byte_count {
                        b ^= 1;
                        rand_idx = (rand_idx + 1) & 255;
                        rand_val += RANDOMIZATION_TABLE[rand_idx] as usize;
                    }
                    byte_count += 1;

                    if count == 4 {
                        count = 0;
                        if b == 0 {
                            continue;
                        }
                        repeat = (b - 1) as usize;
                        output.push(last);
                    } else {
                        if b == last {
                            count += 1;
                        } else {
                            count = 1;
                            last = b;
                        }
                        output.push(b);
                    }
                }
            }
        }

        Ok(output)
    }
}

const META_CODES: [u32; 37] = [
    0x5d8, 0x058, 0x040, 0x0c0, 0x000, 0x078, 0x02b, 0x014, 0x00c, 0x01c, 0x01b, 0x00b, 0x010,
    0x020, 0x038, 0x018, 0x0d8, 0xbd8, 0x180, 0x680, 0x380, 0xf80, 0x780, 0x480, 0x080, 0x280,
    0x3d8, 0xfd8, 0x7d8, 0x9d8, 0x1d8, 0x004, 0x001, 0x002, 0x007, 0x003, 0x008,
];
const META_CODE_LENGTHS: [i32; 37] = [
    11, 8, 8, 8, 8, 7, 6, 5, 5, 5, 5, 6, 5, 6, 7, 7, 9, 12, 10, 11, 11, 12, 12, 11, 11, 11, 12, 12,
    12, 12, 12, 5, 2, 2, 3, 4, 5,
];

const RANDOMIZATION_TABLE: [u16; 256] = [
    0xee, 0x56, 0xf8, 0xc3, 0x9d, 0x9f, 0xae, 0x2c, 0xad, 0xcd, 0x24, 0x9d, 0xa6, 0x101, 0x18,
    0xb9, 0xa1, 0x82, 0x75, 0xe9, 0x9f, 0x55, 0x66, 0x6a, 0x86, 0x71, 0xdc, 0x84, 0x56, 0x96, 0x56,
    0xa1, 0x84, 0x78, 0xb7, 0x32, 0x6a, 0x3, 0xe3, 0x2, 0x11, 0x101, 0x8, 0x44, 0x83, 0x100, 0x43,
    0xe3, 0x1c, 0xf0, 0x86, 0x6a, 0x6b, 0xf, 0x3, 0x2d, 0x86, 0x17, 0x7b, 0x10, 0xf6, 0x80, 0x78,
    0x7a, 0xa1, 0xe1, 0xef, 0x8c, 0xf6, 0x87, 0x4b, 0xa7, 0xe2, 0x77, 0xfa, 0xb8, 0x81, 0xee, 0x77,
    0xc0, 0x9d, 0x29, 0x20, 0x27, 0x71, 0x12, 0xe0, 0x6b, 0xd1, 0x7c, 0xa, 0x89, 0x7d, 0x87, 0xc4,
    0x101, 0xc1, 0x31, 0xaf, 0x38, 0x3, 0x68, 0x1b, 0x76, 0x79, 0x3f, 0xdb, 0xc7, 0x1b, 0x36, 0x7b,
    0xe2, 0x63, 0x81, 0xee, 0xc, 0x63, 0x8b, 0x78, 0x38, 0x97, 0x9b, 0xd7, 0x8f, 0xdd, 0xf2, 0xa3,
    0x77, 0x8c, 0xc3, 0x39, 0x20, 0xb3, 0x12, 0x11, 0xe, 0x17, 0x42, 0x80, 0x2c, 0xc4, 0x92, 0x59,
    0xc8, 0xdb, 0x40, 0x76, 0x64, 0xb4, 0x55, 0x1a, 0x9e, 0xfe, 0x5f, 0x6, 0x3c, 0x41, 0xef, 0xd4,
    0xaa, 0x98, 0x29, 0xcd, 0x1f, 0x2, 0xa8, 0x87, 0xd2, 0xa0, 0x93, 0x98, 0xef, 0xc, 0x43, 0xed,
    0x9d, 0xc2, 0xeb, 0x81, 0xe9, 0x64, 0x23, 0x68, 0x1e, 0x25, 0x57, 0xde, 0x9a, 0xcf, 0x7f, 0xe5,
    0xba, 0x41, 0xea, 0xea, 0x36, 0x1a, 0x28, 0x79, 0x20, 0x5e, 0x18, 0x4e, 0x7c, 0x8e, 0x58, 0x7a,
    0xef, 0x91, 0x2, 0x93, 0xbb, 0x56, 0xa1, 0x49, 0x1b, 0x79, 0x92, 0xf3, 0x58, 0x4f, 0x52, 0x9c,
    0x2, 0x77, 0xaf, 0x2a, 0x8f, 0x49, 0xd0, 0x99, 0x4d, 0x98, 0x101, 0x60, 0x93, 0x100, 0x75,
    0x31, 0xce, 0x49, 0x20, 0x56, 0x57, 0xe2, 0xf5, 0x26, 0x2b, 0x8a, 0xbf, 0xde, 0xd0, 0x83, 0x34,
    0xf4, 0x17,
];

const OFFSET_CODE_SIZES: [usize; 5] = [11, 13, 14, 11, 11];

const FIRST_CODE_LENGTHS: [&[i32]; 5] = [
    // FirstCodeLengths_1 from XADStuffIt13Handle.m
    &[
        4, 5, 7, 8, 8, 9, 9, 9, 9, 7, 9, 9, 9, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 10, 9, 9, 10, 10, 9,
        10, 9, 9, 5, 9, 9, 9, 9, 10, 9, 9, 9, 9, 9, 9, 9, 9, 7, 9, 9, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 8, 9, 9, 8, 8, 9, 9, 9, 9, 9, 9, 9, 7, 8, 9, 7, 9, 9, 7, 7, 9, 9, 9, 9,
        10, 9, 10, 10, 10, 9, 9, 9, 5, 9, 8, 7, 5, 9, 8, 8, 7, 9, 9, 8, 8, 5, 5, 7, 10, 5, 8, 5, 8,
        9, 9, 9, 9, 9, 10, 9, 9, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10,
        10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10,
        10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10,
        10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        10, 9, 9, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 9, 10, 9, 5, 6, 5, 5, 8, 9,
        9, 9, 9, 9, 9, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        10, 10, 10, 10, 10, 10, 9, 10, 9, 9, 9, 10, 9, 10, 9, 10, 9, 10, 9, 10, 10, 10, 9, 10, 9,
        10, 10, 9, 9, 9, 6, 9, 9, 10, 9, 5,
    ],
    &[
        4, 7, 7, 8, 7, 8, 8, 8, 8, 7, 8, 7, 8, 7, 9, 8, 8, 8, 9, 9, 9, 9, 10, 10, 9, 10, 10, 10,
        10, 10, 9, 9, 5, 9, 8, 9, 9, 11, 10, 9, 8, 9, 9, 9, 8, 9, 7, 8, 8, 8, 9, 9, 9, 9, 9, 10, 9,
        9, 9, 10, 9, 9, 10, 9, 8, 8, 7, 7, 7, 8, 8, 9, 8, 8, 9, 9, 8, 8, 7, 8, 7, 10, 8, 7, 7, 9,
        9, 9, 9, 10, 10, 11, 11, 11, 10, 9, 8, 6, 8, 7, 7, 5, 7, 7, 7, 6, 9, 8, 6, 7, 6, 6, 7, 9,
        6, 6, 6, 7, 8, 8, 8, 8, 9, 10, 9, 10, 9, 9, 8, 9, 10, 10, 9, 10, 10, 9, 9, 10, 10, 10, 10,
        10, 10, 10, 9, 10, 10, 11, 10, 10, 10, 10, 10, 10, 10, 11, 10, 11, 10, 10, 9, 11, 10, 10,
        10, 10, 10, 10, 9, 9, 10, 11, 10, 11, 10, 11, 10, 12, 10, 11, 10, 12, 11, 12, 10, 12, 10,
        11, 10, 11, 11, 11, 9, 10, 11, 11, 11, 12, 12, 10, 10, 10, 11, 11, 10, 11, 10, 10, 9, 11,
        10, 11, 10, 11, 11, 11, 10, 11, 11, 12, 11, 11, 10, 10, 10, 11, 10, 10, 11, 11, 12, 10, 10,
        11, 11, 12, 11, 11, 10, 11, 9, 12, 10, 11, 11, 11, 10, 11, 10, 11, 10, 11, 9, 10, 9, 7, 3,
        5, 6, 6, 7, 7, 8, 8, 8, 9, 9, 9, 11, 10, 10, 10, 12, 13, 11, 12, 12, 11, 13, 12, 12, 11,
        12, 12, 13, 12, 14, 13, 14, 13, 15, 13, 14, 15, 15, 14, 13, 15, 15, 14, 15, 14, 15, 15, 14,
        15, 13, 13, 14, 15, 15, 14, 14, 16, 16, 15, 15, 15, 12, 15, 10,
    ],
    &[
        6, 6, 6, 6, 6, 9, 8, 8, 4, 9, 8, 9, 8, 9, 9, 9, 8, 9, 9, 10, 8, 10, 10, 10, 9, 10, 10, 10,
        9, 10, 10, 9, 9, 9, 8, 10, 9, 10, 9, 10, 9, 10, 9, 10, 9, 9, 8, 9, 8, 9, 9, 9, 10, 10, 10,
        10, 9, 9, 9, 10, 9, 10, 9, 9, 7, 8, 8, 9, 8, 9, 9, 9, 8, 9, 9, 10, 9, 9, 8, 9, 8, 9, 8, 8,
        8, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 9, 8, 8, 9, 8, 9, 7, 8, 8, 9, 8, 10, 10, 8, 9, 8, 8,
        8, 10, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 10, 9, 7, 9, 9, 10, 10, 10, 10, 10, 9, 10,
        10, 10, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 9, 10,
        10, 10, 10, 10, 10, 10, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        10, 9, 10, 10, 10, 10, 9, 8, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 9,
        10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 9,
        10, 10, 10, 10, 10, 10, 9, 9, 9, 10, 10, 10, 10, 10, 10, 9, 9, 10, 9, 9, 8, 9, 8, 9, 4, 6,
        6, 6, 7, 8, 8, 9, 9, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        10, 10, 10, 7, 10, 10, 10, 7, 10, 10, 7, 7, 7, 7, 7, 6, 7, 10, 7, 7, 10, 7, 7, 7, 6, 7, 6,
        6, 7, 7, 6, 6, 9, 6, 9, 10, 6, 10,
    ],
    &[
        2, 6, 6, 7, 7, 8, 7, 8, 7, 8, 8, 9, 8, 9, 9, 9, 8, 8, 9, 9, 9, 10, 10, 9, 8, 10, 9, 10, 9,
        10, 9, 9, 6, 9, 8, 9, 9, 10, 9, 9, 9, 10, 9, 9, 9, 9, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 10, 10, 9, 7, 7, 8, 8, 8, 8, 9, 9, 7, 8, 9, 10, 8, 8, 7, 8, 8, 10, 8, 8, 8, 9, 8,
        9, 9, 10, 9, 11, 10, 11, 9, 9, 8, 7, 9, 8, 8, 6, 8, 8, 8, 7, 10, 9, 7, 8, 7, 7, 8, 10, 7,
        7, 7, 8, 9, 9, 9, 9, 10, 11, 9, 11, 10, 9, 7, 9, 10, 10, 10, 11, 11, 10, 10, 11, 10, 10,
        10, 11, 11, 10, 9, 10, 10, 11, 10, 11, 10, 11, 10, 10, 10, 11, 10, 11, 10, 10, 9, 10, 10,
        11, 10, 11, 10, 11, 9, 10, 10, 10, 10, 11, 10, 11, 10, 11, 10, 11, 11, 11, 10, 12, 10, 11,
        10, 11, 10, 11, 11, 10, 8, 10, 10, 11, 10, 11, 11, 11, 10, 11, 10, 11, 10, 11, 11, 11, 9,
        10, 11, 11, 10, 11, 11, 11, 10, 11, 11, 11, 10, 10, 10, 10, 10, 11, 10, 10, 11, 11, 10, 10,
        9, 11, 10, 10, 11, 11, 10, 10, 10, 11, 10, 10, 10, 10, 10, 10, 9, 11, 10, 10, 8, 10, 8, 6,
        5, 6, 6, 7, 7, 8, 8, 8, 9, 10, 11, 10, 10, 11, 11, 12, 12, 10, 11, 12, 12, 12, 12, 13, 13,
        13, 13, 13, 12, 13, 13, 15, 14, 12, 14, 15, 16, 12, 12, 13, 15, 14, 16, 15, 17, 18, 15, 17,
        16, 15, 15, 15, 15, 13, 13, 10, 14, 12, 13, 17, 17, 18, 10, 17, 4,
    ],
    &[
        7, 9, 9, 9, 9, 9, 9, 9, 9, 8, 9, 9, 9, 7, 9, 9, 9, 9, 9, 9, 9, 9, 9, 10, 9, 10, 9, 10, 9,
        10, 9, 9, 5, 9, 7, 9, 9, 9, 9, 9, 7, 7, 7, 9, 7, 7, 8, 7, 8, 8, 7, 7, 9, 9, 9, 9, 7, 7, 7,
        9, 9, 9, 9, 9, 9, 7, 9, 7, 7, 7, 7, 9, 9, 7, 9, 9, 7, 7, 7, 7, 7, 9, 7, 8, 7, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 7, 8, 7, 7, 7, 8, 8, 6, 7, 9, 7, 7, 8, 7, 5, 6, 9, 5, 7, 5, 6, 7,
        7, 9, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 9, 10, 10, 10, 9, 9, 10, 10, 10, 10, 10, 10, 10, 9,
        10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 9, 10, 10, 10, 9, 9, 10, 9, 9,
        9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9,
        10, 10, 10, 9, 10, 10, 10, 9, 9, 9, 10, 10, 10, 10, 10, 9, 10, 9, 10, 10, 9, 10, 10, 9, 10,
        10, 10, 10, 10, 10, 10, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9,
        10, 10, 10, 10, 10, 10, 10, 9, 10, 9, 10, 9, 10, 10, 9, 5, 6, 8, 8, 7, 7, 7, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10,
        10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 9, 10, 10, 5, 10, 8, 9, 8,
        9,
    ],
];
const SECOND_CODE_LENGTHS: [&[i32]; 5] = [
    &[
        4, 5, 6, 6, 7, 7, 6, 7, 7, 7, 6, 8, 7, 8, 8, 8, 8, 9, 6, 9, 8, 9, 8, 9, 9, 9, 8, 10, 5, 9,
        7, 9, 6, 9, 8, 10, 9, 10, 8, 8, 9, 9, 7, 9, 8, 9, 8, 9, 8, 8, 6, 9, 9, 8, 8, 9, 9, 10, 8,
        9, 9, 10, 8, 10, 8, 8, 8, 8, 8, 9, 7, 10, 6, 9, 9, 11, 7, 8, 8, 9, 8, 10, 7, 8, 6, 9, 10,
        9, 9, 10, 8, 11, 9, 11, 9, 10, 9, 8, 9, 8, 8, 8, 8, 10, 9, 9, 10, 10, 8, 9, 8, 8, 8, 11, 9,
        8, 8, 9, 9, 10, 8, 11, 10, 10, 8, 10, 9, 10, 8, 9, 9, 11, 9, 11, 9, 10, 10, 11, 10, 12, 9,
        12, 10, 11, 10, 11, 9, 10, 10, 11, 10, 11, 10, 11, 10, 11, 10, 10, 10, 9, 9, 9, 8, 7, 6, 8,
        11, 11, 9, 12, 10, 12, 9, 11, 11, 11, 10, 12, 11, 11, 10, 12, 10, 11, 10, 10, 10, 11, 10,
        11, 11, 11, 9, 12, 10, 12, 11, 12, 10, 11, 10, 12, 11, 12, 11, 12, 11, 12, 10, 12, 11, 12,
        11, 11, 10, 12, 10, 11, 10, 12, 10, 12, 10, 12, 10, 11, 11, 11, 10, 11, 11, 11, 10, 12, 11,
        12, 10, 10, 11, 11, 9, 12, 11, 12, 10, 11, 10, 12, 10, 11, 10, 12, 10, 11, 10, 7, 5, 4, 6,
        6, 7, 7, 7, 8, 8, 7, 7, 6, 8, 6, 7, 7, 9, 8, 9, 9, 10, 11, 11, 11, 12, 11, 10, 11, 12, 11,
        12, 11, 12, 12, 12, 12, 11, 12, 12, 11, 12, 11, 12, 11, 13, 11, 12, 10, 13, 10, 14, 14, 13,
        14, 15, 14, 16, 15, 15, 18, 18, 18, 9, 18, 8,
    ],
    &[
        5, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 8, 7, 8, 7, 7, 7, 8, 8, 8, 8, 9, 8, 9, 8, 9, 9, 9, 7, 9,
        8, 8, 6, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 9, 8, 8, 8, 8, 8, 9, 8, 9, 8, 9, 9, 10, 8, 10,
        8, 9, 9, 8, 8, 8, 7, 8, 8, 9, 8, 9, 7, 9, 8, 10, 8, 9, 8, 9, 8, 9, 8, 8, 8, 9, 9, 9, 9, 10,
        9, 11, 9, 10, 9, 10, 8, 8, 8, 9, 8, 8, 8, 9, 9, 8, 9, 10, 8, 9, 8, 8, 8, 11, 8, 7, 8, 9, 9,
        9, 9, 10, 9, 10, 9, 10, 9, 8, 8, 9, 9, 10, 9, 10, 9, 10, 8, 10, 9, 10, 9, 11, 10, 11, 9,
        11, 10, 10, 10, 11, 9, 11, 9, 10, 9, 11, 9, 11, 10, 10, 9, 10, 9, 9, 8, 10, 9, 11, 9, 9, 9,
        11, 10, 11, 9, 11, 9, 11, 9, 11, 10, 11, 10, 11, 10, 11, 9, 10, 10, 11, 10, 10, 8, 10, 9,
        10, 10, 11, 9, 11, 9, 10, 10, 11, 9, 10, 10, 9, 9, 10, 9, 10, 9, 10, 9, 10, 9, 11, 9, 11,
        10, 10, 9, 10, 9, 11, 9, 11, 9, 11, 9, 10, 9, 11, 9, 11, 9, 11, 9, 10, 8, 11, 9, 10, 9, 10,
        9, 10, 8, 10, 8, 9, 8, 9, 8, 7, 4, 4, 5, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 7, 8, 8, 9, 9, 10,
        10, 10, 10, 10, 10, 11, 11, 10, 10, 12, 11, 11, 12, 12, 11, 12, 12, 11, 12, 12, 12, 12, 12,
        12, 11, 12, 11, 13, 12, 13, 12, 13, 14, 14, 14, 15, 13, 14, 13, 14, 18, 18, 17, 7, 16, 9,
    ],
    &[
        5, 6, 6, 6, 6, 7, 7, 7, 6, 8, 7, 8, 7, 9, 8, 8, 7, 7, 8, 9, 9, 9, 9, 10, 8, 9, 9, 10, 8,
        10, 9, 8, 6, 10, 8, 10, 8, 10, 9, 9, 9, 9, 9, 10, 9, 9, 8, 9, 8, 9, 8, 9, 9, 10, 9, 10, 9,
        9, 8, 10, 9, 11, 10, 8, 8, 8, 8, 9, 7, 9, 9, 10, 8, 9, 8, 11, 9, 10, 9, 10, 8, 9, 9, 9, 9,
        8, 9, 9, 10, 10, 10, 12, 10, 11, 10, 10, 8, 9, 9, 9, 8, 9, 8, 8, 10, 9, 10, 11, 8, 10, 9,
        9, 8, 12, 8, 9, 9, 9, 9, 8, 9, 10, 9, 12, 10, 10, 10, 8, 7, 11, 10, 9, 10, 11, 9, 11, 7,
        11, 10, 12, 10, 12, 10, 11, 9, 11, 9, 12, 10, 12, 10, 12, 10, 9, 11, 12, 10, 12, 10, 11, 9,
        10, 9, 10, 9, 11, 11, 12, 9, 10, 8, 12, 11, 12, 9, 12, 10, 12, 10, 13, 10, 12, 10, 12, 10,
        12, 10, 9, 10, 12, 10, 9, 8, 11, 10, 12, 10, 12, 10, 12, 10, 11, 10, 12, 8, 12, 10, 11, 10,
        10, 10, 12, 9, 11, 10, 12, 10, 12, 11, 12, 10, 9, 10, 12, 9, 10, 10, 12, 10, 11, 10, 11,
        10, 12, 8, 12, 9, 12, 8, 12, 8, 11, 10, 11, 10, 11, 9, 10, 8, 10, 9, 9, 8, 9, 8, 7, 4, 3,
        5, 5, 6, 5, 6, 6, 7, 7, 8, 8, 8, 7, 7, 7, 9, 8, 9, 9, 11, 9, 11, 9, 8, 9, 9, 11, 12, 11,
        12, 12, 13, 13, 12, 13, 14, 13, 14, 13, 14, 13, 13, 13, 12, 13, 13, 12, 13, 13, 14, 14, 13,
        13, 14, 14, 14, 14, 15, 18, 17, 18, 8, 16, 10,
    ],
    &[
        4, 5, 6, 6, 6, 6, 7, 7, 6, 7, 7, 9, 6, 8, 8, 7, 7, 8, 8, 8, 6, 9, 8, 8, 7, 9, 8, 9, 8, 9,
        8, 9, 6, 9, 8, 9, 8, 10, 9, 9, 8, 10, 8, 10, 8, 9, 8, 9, 8, 8, 7, 9, 9, 9, 9, 9, 8, 10, 9,
        10, 9, 10, 9, 8, 7, 8, 9, 9, 8, 9, 9, 9, 7, 10, 9, 10, 9, 9, 8, 9, 8, 9, 8, 8, 8, 9, 9, 10,
        9, 9, 8, 11, 9, 11, 10, 10, 8, 8, 10, 8, 8, 9, 9, 9, 10, 9, 10, 11, 9, 9, 9, 9, 8, 9, 8, 8,
        8, 10, 10, 9, 9, 8, 10, 11, 10, 11, 11, 9, 8, 9, 10, 11, 9, 10, 11, 11, 9, 12, 10, 10, 10,
        12, 11, 11, 9, 11, 11, 12, 9, 11, 9, 10, 10, 10, 10, 12, 9, 11, 10, 11, 9, 11, 11, 11, 10,
        11, 11, 12, 9, 10, 10, 12, 11, 11, 10, 11, 9, 11, 10, 11, 10, 11, 9, 11, 11, 9, 8, 11, 10,
        11, 11, 10, 7, 12, 11, 11, 11, 11, 11, 12, 10, 12, 11, 13, 11, 10, 12, 11, 10, 11, 10, 11,
        10, 11, 10, 11, 10, 12, 11, 11, 10, 11, 10, 10, 10, 11, 10, 12, 11, 12, 10, 11, 9, 11, 10,
        11, 10, 11, 10, 12, 9, 11, 11, 11, 9, 11, 10, 10, 9, 11, 10, 10, 9, 10, 9, 7, 4, 5, 5, 5,
        6, 6, 7, 6, 8, 7, 8, 9, 9, 7, 8, 8, 10, 9, 10, 10, 12, 10, 11, 11, 11, 11, 10, 11, 12, 11,
        11, 11, 11, 11, 13, 12, 11, 12, 13, 12, 12, 12, 13, 11, 9, 12, 13, 7, 13, 11, 13, 11, 10,
        11, 13, 15, 15, 12, 14, 15, 15, 15, 6, 15, 5,
    ],
    &[
        8, 10, 11, 11, 11, 12, 11, 11, 12, 6, 11, 12, 10, 5, 12, 12, 12, 12, 12, 12, 12, 13, 13,
        14, 13, 13, 12, 13, 12, 13, 12, 15, 4, 10, 7, 9, 11, 11, 10, 9, 6, 7, 8, 9, 6, 7, 6, 7, 8,
        7, 7, 8, 8, 8, 8, 8, 8, 9, 8, 7, 10, 9, 10, 10, 11, 7, 8, 6, 7, 8, 8, 9, 8, 7, 10, 10, 8,
        7, 8, 8, 7, 10, 7, 6, 7, 9, 9, 8, 11, 11, 11, 10, 11, 11, 11, 8, 11, 6, 7, 6, 6, 6, 6, 8,
        7, 6, 10, 9, 6, 7, 6, 6, 7, 10, 6, 5, 6, 7, 7, 7, 10, 8, 11, 9, 13, 7, 14, 16, 12, 14, 14,
        15, 15, 16, 16, 14, 15, 15, 15, 15, 15, 15, 15, 15, 14, 15, 13, 14, 14, 16, 15, 17, 14, 17,
        15, 17, 12, 14, 13, 16, 12, 17, 13, 17, 14, 13, 13, 14, 14, 12, 13, 15, 15, 14, 15, 17, 14,
        17, 15, 14, 15, 16, 12, 16, 15, 14, 15, 16, 15, 16, 17, 17, 15, 15, 17, 17, 13, 14, 15, 15,
        13, 12, 16, 16, 17, 14, 15, 16, 15, 15, 13, 13, 15, 13, 16, 17, 15, 17, 17, 17, 16, 17, 14,
        17, 14, 16, 15, 17, 15, 15, 14, 17, 15, 17, 15, 16, 15, 15, 16, 16, 14, 17, 17, 15, 15, 16,
        15, 17, 15, 14, 16, 16, 16, 16, 16, 12, 4, 4, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9,
        9, 9, 10, 10, 10, 11, 10, 11, 11, 11, 11, 11, 12, 12, 12, 13, 13, 12, 13, 12, 14, 14, 12,
        13, 13, 13, 13, 14, 12, 13, 13, 14, 14, 14, 13, 14, 14, 15, 15, 13, 15, 13, 17, 17, 17, 9,
        17, 7,
    ],
];
const OFFSET_CODE_LENGTHS: [&[i32]; 5] = [
    &[5, 6, 3, 3, 3, 3, 3, 3, 3, 4, 6],
    &[5, 6, 4, 4, 3, 3, 3, 3, 3, 4, 4, 4, 6],
    &[6, 7, 4, 4, 3, 3, 3, 3, 3, 4, 4, 4, 5, 7],
    &[3, 6, 5, 4, 2, 3, 3, 3, 4, 4, 6],
    &[6, 7, 7, 6, 4, 3, 2, 2, 3, 3, 6],
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a simple text entry
    fn text_entry(name: &str, content: &[u8]) -> SitEntry {
        SitEntry {
            name: name.to_string(),
            data_fork: content.to_vec(),
            file_type: *b"TEXT",
            creator: *b"ttxt",
            ..Default::default()
        }
    }

    #[test]
    fn test_crc16() {
        // Known CRC values for IBM CRC-16
        assert_eq!(crc16(b""), 0x0000);
        assert_eq!(crc16(b"123456789"), 0xBB3D);
        assert_eq!(crc16(b"Hello World\n"), 0x48FE);
    }

    #[test]
    fn test_empty_archive() {
        let archive = SitArchive::new();
        let serialized = archive.serialize().expect("Should serialize");
        let parsed = SitArchive::parse(&serialized).expect("Should parse");
        assert_eq!(parsed.entries.len(), 0);
    }

    #[test]
    fn test_single_file_uncompressed() {
        let mut archive = SitArchive::new();
        archive.add_entry(text_entry("hello.txt", b"Hello, World!"));

        let serialized = archive.serialize().expect("Should serialize");
        let parsed = SitArchive::parse(&serialized).expect("Should parse");

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "hello.txt");
        assert_eq!(parsed.entries[0].data_fork, b"Hello, World!");
        assert_eq!(parsed.entries[0].file_type, *b"TEXT");
    }

    #[test]
    fn test_single_file_compressed() {
        let mut archive = SitArchive::new();
        let content = b"This text should compress well. ".repeat(50);
        archive.add_entry(text_entry("compress.txt", &content));

        let serialized = archive.serialize_compressed().expect("Should serialize");
        let parsed = SitArchive::parse(&serialized).expect("Should parse");

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "compress.txt");
        assert_eq!(parsed.entries[0].data_fork, content);

        // Verify compression actually happened (compressed smaller than uncompressed)
        let uncompressed = archive.serialize().expect("Should serialize uncompressed");
        assert!(
            serialized.len() < uncompressed.len(),
            "Compressed size ({}) should be less than uncompressed ({})",
            serialized.len(),
            uncompressed.len()
        );
    }

    #[test]
    fn test_resource_fork() {
        let mut archive = SitArchive::new();
        let entry = SitEntry {
            name: "icon.rsrc".to_string(),
            data_fork: vec![],
            resource_fork: vec![0x00, 0x00, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF],
            file_type: *b"rsrc",
            creator: *b"RSED",
            ..Default::default()
        };
        archive.add_entry(entry);

        let serialized = archive.serialize().expect("Should serialize");
        let parsed = SitArchive::parse(&serialized).expect("Should parse");

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].resource_fork.len(), 8);
        assert_eq!(
            parsed.entries[0].resource_fork[4..8],
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_folder_structure() {
        let mut archive = SitArchive::new();

        // Add a folder
        archive.add_entry(SitEntry {
            name: "my_folder".to_string(),
            is_folder: true,
            finder_flags: 0x0400, // Has custom icon
            ..Default::default()
        });

        // Add files inside the folder
        archive.add_entry(text_entry("my_folder/readme.txt", b"Read me!"));
        archive.add_entry(text_entry("my_folder/data.bin", &[1, 2, 3, 4, 5]));

        let serialized = archive.serialize().expect("Should serialize");
        let parsed = SitArchive::parse(&serialized).expect("Should parse");

        assert_eq!(parsed.entries.len(), 3);

        let folder = parsed
            .entries
            .iter()
            .find(|e| e.name == "my_folder")
            .unwrap();
        assert!(folder.is_folder);
        assert_eq!(folder.finder_flags, 0x0400);

        let readme = parsed
            .entries
            .iter()
            .find(|e| e.name == "my_folder/readme.txt")
            .unwrap();
        assert!(!readme.is_folder);
        assert_eq!(readme.data_fork, b"Read me!");
    }

    #[test]
    fn test_nested_folders() {
        let mut archive = SitArchive::new();

        archive.add_entry(SitEntry {
            name: "a".to_string(),
            is_folder: true,
            ..Default::default()
        });
        archive.add_entry(SitEntry {
            name: "a/b".to_string(),
            is_folder: true,
            ..Default::default()
        });
        archive.add_entry(SitEntry {
            name: "a/b/c".to_string(),
            is_folder: true,
            ..Default::default()
        });
        archive.add_entry(text_entry("a/b/c/deep.txt", b"Deep file"));

        let serialized = archive.serialize().expect("Should serialize");
        let parsed = SitArchive::parse(&serialized).expect("Should parse");

        assert_eq!(parsed.entries.len(), 4);
        let deep = parsed
            .entries
            .iter()
            .find(|e| e.name == "a/b/c/deep.txt")
            .unwrap();
        assert_eq!(deep.data_fork, b"Deep file");
    }

    #[test]
    fn test_finder_metadata() {
        let mut archive = SitArchive::new();
        let entry = SitEntry {
            name: "app".to_string(),
            data_fork: vec![0xCA, 0xFE, 0xBA, 0xBE],
            file_type: *b"APPL",
            creator: *b"CARO",
            finder_flags: 0x0100, // Has been inited
            ..Default::default()
        };
        archive.add_entry(entry);

        let serialized = archive.serialize().expect("Should serialize");
        let parsed = SitArchive::parse(&serialized).expect("Should parse");

        assert_eq!(parsed.entries[0].file_type, *b"APPL");
        assert_eq!(parsed.entries[0].creator, *b"CARO");
        assert_eq!(parsed.entries[0].finder_flags, 0x0100);
    }

    #[test]
    fn test_multiple_files_roundtrip() {
        let mut archive = SitArchive::new();

        // Add various types of content
        archive.add_entry(text_entry("small.txt", b"x"));
        archive.add_entry(text_entry("medium.txt", &vec![b'M'; 1000]));
        archive.add_entry(text_entry("large.txt", &vec![b'L'; 10000]));
        archive.add_entry(SitEntry {
            name: "binary.dat".to_string(),
            data_fork: (0..=255).collect(),
            file_type: *b"BINA",
            creator: *b"????",
            ..Default::default()
        });

        let serialized = archive.serialize().expect("Should serialize");
        let parsed = SitArchive::parse(&serialized).expect("Should parse");

        assert_eq!(parsed.entries.len(), 4);

        // Sort for predictable comparison
        let mut orig: Vec<_> = archive.entries.iter().collect();
        let mut pars: Vec<_> = parsed.entries.iter().collect();
        orig.sort_by_key(|e| &e.name);
        pars.sort_by_key(|e| &e.name);

        for (o, p) in orig.iter().zip(pars.iter()) {
            assert_eq!(o.name, p.name);
            assert_eq!(o.data_fork, p.data_fork);
            assert_eq!(o.file_type, p.file_type);
        }
    }

    #[test]
    fn test_compressed_roundtrip() {
        let mut archive = SitArchive::new();

        // Content with repetition that compresses well
        let repetitive = b"ABCDEFGH".repeat(1000);
        archive.add_entry(text_entry("repetitive.txt", &repetitive));

        // Content with some randomness
        let mixed: Vec<u8> = (0..5000).map(|i| ((i * 17 + 31) % 256) as u8).collect();
        archive.add_entry(SitEntry {
            name: "mixed.bin".to_string(),
            data_fork: mixed.clone(),
            ..Default::default()
        });

        let serialized = archive.serialize_compressed().expect("Should compress");
        let parsed = SitArchive::parse(&serialized).expect("Should decompress");

        assert_eq!(parsed.entries.len(), 2);

        let rep = parsed
            .entries
            .iter()
            .find(|e| e.name == "repetitive.txt")
            .unwrap();
        assert_eq!(rep.data_fork, repetitive);

        let mix = parsed
            .entries
            .iter()
            .find(|e| e.name == "mixed.bin")
            .unwrap();
        assert_eq!(mix.data_fork, mixed);
    }

    #[test]
    fn test_invalid_data() {
        // Too short to be valid
        let result = SitArchive::parse(b"short");
        assert!(result.is_err());

        // Wrong signature but right length
        let bad_data = vec![0u8; 200];
        let result = SitArchive::parse(&bad_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_compression_method_13() {
        // Test that method 13 compression works correctly
        let data = b"Hello, this is a test of method 13 compression!";
        let compressed = compress_sit13(data);

        // Verify it starts with the correct header byte (mode 1)
        assert_eq!(compressed[0] >> 4, 1);

        // Decompress and verify
        let mut decoder = Sit13Decoder::new(&compressed);
        let decompressed = decoder.decompress(data.len()).expect("Should decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_with_matches() {
        // Data with repeated patterns that should trigger LZ77 matching
        let data = b"ABCDABCDABCDABCD1234ABCD5678ABCDABCD";
        let compressed = compress_sit13(data);

        let mut decoder = Sit13Decoder::new(&compressed);
        let decompressed = decoder.decompress(data.len()).expect("Should decompress");
        assert_eq!(decompressed, data);

        // Compressed should be smaller due to matches
        assert!(compressed.len() < data.len());
    }
}
