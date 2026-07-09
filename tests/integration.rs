use std::fs;
use std::path::Path;
use stuffit::{SitArchive, SitEntry};

const FIXTURES_DIR: &str = "tests/fixtures";

// ============================================================================
// Shared Utilities
// ============================================================================

mod utils {
    /// IBM CRC16 algorithm (polynomial 0xA001, reflected)
    pub fn crc16(data: &[u8]) -> u16 {
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

    /// Helper for writing variable-length bit sequences (little-endian)
    pub struct BitWriter {
        data: Vec<u8>,
        bit_buf: u64,
        bits_in_buf: u32,
    }

    impl BitWriter {
        pub fn new() -> Self {
            Self {
                data: Vec::new(),
                bit_buf: 0,
                bits_in_buf: 0,
            }
        }

        pub fn write_bits_le(&mut self, val: u32, n: u32) {
            let val = val as u64 & ((1u64 << n) - 1);
            self.bit_buf |= val << self.bits_in_buf;
            self.bits_in_buf += n;
            while self.bits_in_buf >= 8 {
                let byte = self.bit_buf as u8;
                self.data.push(byte);
                self.bit_buf >>= 8;
                self.bits_in_buf -= 8;
            }
        }

        pub fn flush(&mut self) {
            if self.bits_in_buf > 0 {
                self.data.push(self.bit_buf as u8);
                self.bits_in_buf = 0;
                self.bit_buf = 0;
            }
        }

        pub fn into_data(mut self) -> Vec<u8> {
            self.flush();
            self.data
        }
    }

    /// Simple LZW encoder for testing Method 2 (LZW) archives
    pub fn lzw_encode(data: &[u8]) -> Vec<u8> {
        let mut writer = BitWriter::new();
        for block in data.chunks(10) {
            lzw_encode_block(block, &mut writer);
        }
        writer.into_data()
    }

    fn lzw_encode_block(data: &[u8], writer: &mut BitWriter) {
        use std::collections::HashMap;

        if data.is_empty() {
            return;
        }

        let mut dict: HashMap<Vec<u8>, u32> = HashMap::new();

        // Initialize dictionary with single-byte sequences
        for i in 0..256 {
            dict.insert(vec![i as u8], i as u32);
        }

        let mut next_code = 257; // 256=end-of-block/reset marker
        let mut code_size = 9u32;
        let mut codes_in_block = 0u32;

        let mut current = vec![data[0]];

        for &b in &data[1..] {
            let mut next = current.clone();
            next.push(b);

            if dict.contains_key(&next) {
                current = next;
            } else {
                // Emit code for current sequence
                let code = *dict.get(&current).unwrap();
                writer.write_bits_le(code, code_size);
                codes_in_block += 1;

                // Add new sequence to dictionary
                if next_code < 16384 {
                    dict.insert(next, next_code);
                    next_code += 1;

                    // Increase bit width when needed
                    if next_code.is_power_of_two() && next_code < 16384 && code_size < 14 {
                        code_size += 1;
                    }
                }

                current = vec![b];
            }
        }

        // Emit final sequence
        if !current.is_empty() {
            let code = *dict.get(&current).unwrap();
            writer.write_bits_le(code, code_size);
            codes_in_block += 1;
        }

        writer.write_bits_le(256, code_size);
        codes_in_block += 1;

        if codes_in_block % 8 != 0 {
            for _ in 0..(8 - (codes_in_block % 8)) {
                writer.write_bits_le(0, code_size);
            }
        }
    }
}

// ============================================================================
// Roundtrip Tests (Create + Parse)
// ============================================================================

mod roundtrip {
    use super::*;

    #[test]
    fn test_method_0_store() {
        let mut archive = SitArchive::new();
        let content = b"Hello World from Method 0 (Store)!".to_vec();

        let entry = SitEntry {
            name: "hello_m0.txt".to_string(),
            data_fork: content.clone(),
            file_type: *b"TEXT",
            creator: *b"ttxt",
            ..Default::default()
        };
        archive.add_entry(entry);

        let data = archive
            .serialize_with_method(0)
            .expect("Failed to serialize M0");
        let parsed = SitArchive::parse(&data).expect("Failed to parse SIT");

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "hello_m0.txt");
        assert_eq!(parsed.entries[0].data_method, 0);

        let (parsed_data, _) = parsed.entries[0]
            .decompressed_forks()
            .expect("Should decompress");
        assert_eq!(parsed_data, content);
    }

    #[test]
    fn test_method_13_compressed() {
        let mut archive = SitArchive::new();
        let content = b"Repetitive Repetitive Repetitive Repetitive Repetitive Content generic generic generic".to_vec();

        let entry = SitEntry {
            name: "hello_m13.txt".to_string(),
            data_fork: content.clone(),
            file_type: *b"TEXT",
            creator: *b"ttxt",
            ..Default::default()
        };
        archive.add_entry(entry);

        let data = archive
            .serialize_with_method(13)
            .expect("Failed to serialize M13");
        let parsed = SitArchive::parse(&data).expect("Failed to parse SIT");

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "hello_m13.txt");

        let (parsed_data, _) = parsed.entries[0]
            .decompressed_forks()
            .expect("Should decompress");
        assert_eq!(parsed_data, content);
    }

    #[test]
    fn test_method_14_deflate() {
        let mut archive = SitArchive::new();
        let content = b"Hello, Deflate! This text should be compressed using Method 14.".to_vec();

        let entry = SitEntry {
            name: "test_deflate.txt".to_string(),
            data_fork: content.clone(),
            file_type: *b"TEXT",
            creator: *b"ttxt",
            ..Default::default()
        };
        archive.add_entry(entry);

        let serialized = archive
            .serialize_with_method(14)
            .expect("Failed to serialize with method 14");
        let parsed = SitArchive::parse(&serialized).expect("Failed to parse generated archive");

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "test_deflate.txt");
        assert_eq!(parsed.entries[0].data_method & 0x0F, 14);

        let (parsed_data, _) = parsed.entries[0]
            .decompressed_forks()
            .expect("Should decompress");
        assert_eq!(parsed_data, content);
    }

    #[test]
    fn test_method_15_bwt() {
        let mut archive = SitArchive::new();
        let content = b"ABCABCABCABCABCABCABCABC The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.".to_vec();

        let entry = SitEntry {
            name: "test_bwt.txt".to_string(),
            data_fork: content.clone(),
            file_type: *b"TEXT",
            creator: *b"ttxt",
            ..Default::default()
        };
        archive.add_entry(entry);

        let serialized = archive
            .serialize_with_method(15)
            .expect("Failed to serialize with method 15");
        let parsed = SitArchive::parse(&serialized).expect("Failed to parse generated archive");

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "test_bwt.txt");
        assert_eq!(parsed.entries[0].data_method & 0x0F, 15);

        let (parsed_data, _) = parsed.entries[0]
            .decompressed_forks()
            .expect("Should decompress");
        assert_eq!(parsed_data, content);
    }
}

// ============================================================================
// Legacy Compression Method Tests (SIT! 1.x format)
// ============================================================================

mod legacy_compression {
    use super::*;
    use utils::*;

    /// Test parsing Method 1 (RLE) compressed data
    /// RLE uses 0x90 as escape: A, 0x90, 5, B -> A, B, B, B, B, B
    #[test]
    fn test_method_1_rle() {
        let mut data = Vec::new();

        // Archive header (22 bytes)
        data.extend_from_slice(b"SIT!");
        data.extend_from_slice(&[0, 1]); // 1 file

        // Entry header (112 bytes)
        let mut entry_header = vec![0u8; 112];
        entry_header[0] = 0; // rsrc method
        entry_header[1] = 1; // data method (RLE)
        entry_header[2] = 3; // filename length
        entry_header[3..6].copy_from_slice(b"rle");

        // Data uncompressed length: 6 bytes ("ABBBBB")
        entry_header[88..92].copy_from_slice(&6u32.to_be_bytes());

        // Data compressed length: 4 bytes (A, 0x90, 5, B)
        entry_header[96..100].copy_from_slice(&4u32.to_be_bytes());

        // Header CRC
        let crc = crc16(&entry_header[0..110]);
        entry_header[110..112].copy_from_slice(&crc.to_be_bytes());

        // Total size
        let total_size: u32 = 22 + 112 + 4;
        data.extend_from_slice(&total_size.to_be_bytes());
        data.extend_from_slice(&[0u8; 12]); // padding
        data.extend_from_slice(&entry_header);

        // Compressed data: A, 0x90, 5, B
        data.extend_from_slice(&[b'A', 0x90, 5, b'B']);

        // Parse and verify
        let archive = SitArchive::parse(&data).expect("Failed to parse RLE archive");
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].data_method, 1);
        assert_eq!(archive.entries[0].data_ulen, 6);

        let (decompressed, _) = archive.entries[0]
            .decompressed_forks()
            .expect("Should decompress");
        assert_eq!(decompressed, b"ABBBBB");
    }

    /// Test parsing Method 2 (LZW) compressed data
    #[test]
    fn test_method_2_lzw() {
        let original_data = b"ABBBBBBBBBBBBBAAAAAAA".to_vec();
        let compressed_data = lzw_encode(&original_data);

        let mut data = Vec::new();

        // Archive header (22 bytes)
        data.extend_from_slice(b"SIT!");
        data.extend_from_slice(&[0, 1]); // 1 file

        // Entry header (112 bytes)
        let mut entry_header = vec![0u8; 112];
        entry_header[0] = 0; // rsrc method
        entry_header[1] = 2; // data method (LZW)
        entry_header[2] = 7; // filename length
        entry_header[3..10].copy_from_slice(b"lzw.txt");

        // Sizes
        entry_header[88..92].copy_from_slice(&(original_data.len() as u32).to_be_bytes());
        entry_header[96..100].copy_from_slice(&(compressed_data.len() as u32).to_be_bytes());

        // Header CRC
        let crc = crc16(&entry_header[0..110]);
        entry_header[110..112].copy_from_slice(&crc.to_be_bytes());

        // Total size
        let total_size: u32 = 22 + 112 + compressed_data.len() as u32;
        data.extend_from_slice(&total_size.to_be_bytes());
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&entry_header);
        data.extend_from_slice(&compressed_data);

        // Parse and verify
        let archive = SitArchive::parse(&data).expect("Failed to parse LZW archive");
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].data_method, 2);

        let (decompressed, _) = archive.entries[0]
            .decompressed_forks()
            .expect("Should decompress");
        assert_eq!(decompressed, original_data);
    }

    /// Regression test for method 3 Huffman streams.
    ///
    /// Method 3 stores a recursive big-endian bit tree, not the method 13
    /// meta-code length table. The previous decoder tried to parse this payload
    /// as method 13 metadata and panicked while constructing an invalid Huffman
    /// table. The fixture is a one-entry classic SIT archive whose data fork is
    /// a single-leaf tree for ASCII 'A' followed by no additional symbol bits.
    #[test]
    fn test_method_3_huffman_recursive_be_tree_no_panic() {
        let path = Path::new(FIXTURES_DIR).join("test_m3_huffman.sit");
        let data = fs::read(&path).expect("test_m3_huffman.sit fixture missing");
        let archive = SitArchive::parse(&data).expect("Failed to parse Huffman archive");

        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "huff.txt");
        assert_eq!(archive.entries[0].data_method, 3);
        assert_eq!(archive.entries[0].data_fork, [0xA0, 0x80]);

        let (decompressed, _) = archive.entries[0]
            .decompressed_forks()
            .expect("Should decompress method 3 Huffman data");
        assert_eq!(decompressed, b"AAAAAAAA");
    }
}

// ============================================================================
// Timestamp Tests
// ============================================================================

mod timestamps {
    use super::*;
    use utils::*;

    /// SIT! classic entry headers store the creation date at bytes 76-79 and
    /// the modification date at bytes 80-83, for folders and files alike.
    #[test]
    fn test_classic_timestamps() {
        let mut data = Vec::new();

        // Archive header (22 bytes)
        data.extend_from_slice(b"SIT!");
        data.extend_from_slice(&[0, 2]); // 2 files

        // Folder start marker
        let mut folder_header = vec![0u8; 112];
        folder_header[0] = 0x20; // rsrc method: folder start
        folder_header[1] = 0x20; // data method: folder start
        folder_header[2] = 3; // filename length
        folder_header[3..6].copy_from_slice(b"Dir");
        folder_header[76..80].copy_from_slice(&0xd0000001u32.to_be_bytes());
        folder_header[80..84].copy_from_slice(&0xd0000002u32.to_be_bytes());
        let crc = crc16(&folder_header[0..110]);
        folder_header[110..112].copy_from_slice(&crc.to_be_bytes());

        // File inside the folder, stored uncompressed
        let contents = b"hi";
        let mut file_header = vec![0u8; 112];
        file_header[2] = 8; // filename length
        file_header[3..11].copy_from_slice(b"file.txt");
        file_header[76..80].copy_from_slice(&0xd1111111u32.to_be_bytes());
        file_header[80..84].copy_from_slice(&0xd2222222u32.to_be_bytes());
        file_header[88..92].copy_from_slice(&(contents.len() as u32).to_be_bytes());
        file_header[96..100].copy_from_slice(&(contents.len() as u32).to_be_bytes());
        let crc = crc16(&file_header[0..110]);
        file_header[110..112].copy_from_slice(&crc.to_be_bytes());

        // Folder end marker
        let mut end_header = vec![0u8; 112];
        end_header[0] = 0x21;
        end_header[1] = 0x21;
        let crc = crc16(&end_header[0..110]);
        end_header[110..112].copy_from_slice(&crc.to_be_bytes());

        let total_size: u32 = 22 + 3 * 112 + contents.len() as u32;
        data.extend_from_slice(&total_size.to_be_bytes());
        data.extend_from_slice(&[0u8; 12]); // padding
        data.extend_from_slice(&folder_header);
        data.extend_from_slice(&file_header);
        data.extend_from_slice(contents);
        data.extend_from_slice(&end_header);

        let archive = SitArchive::parse(&data).expect("Failed to parse classic archive");
        assert_eq!(archive.entries.len(), 2);

        assert_eq!(archive.entries[0].name, "Dir");
        assert!(archive.entries[0].is_folder);
        assert_eq!(archive.entries[0].creation_date, 0xd0000001);
        assert_eq!(archive.entries[0].modification_date, 0xd0000002);

        assert_eq!(archive.entries[1].name, "Dir/file.txt");
        assert_eq!(archive.entries[1].creation_date, 0xd1111111);
        assert_eq!(archive.entries[1].modification_date, 0xd2222222);
    }

    /// The SIT5 fixtures were generated when the writer hardcoded
    /// 0xd256a35a (2015-10-28T16:07:54Z) for both dates; parsing must
    /// surface that value.
    #[test]
    fn test_sit5_fixture_timestamps() {
        let path = Path::new(FIXTURES_DIR).join("test_m13.sit");
        let data = fs::read(&path).expect("test_m13.sit fixture missing");
        let archive = SitArchive::parse(&data).expect("Failed to parse fixture");

        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].creation_date, 0xd256a35a);
        assert_eq!(archive.entries[0].modification_date, 0xd256a35a);
        assert_eq!(
            stuffit::mac_time_to_unix(archive.entries[0].modification_date),
            1_446_048_474
        );
    }
}

// ============================================================================
// Encoding Tests
// ============================================================================

mod encoding {
    use super::*;
    use utils::*;

    /// Test MacRoman encoding for filenames in SIT! Classic archives
    #[test]
    fn test_macroman_encoding() {
        let mut data = Vec::new();

        // Archive header (22 bytes)
        data.extend_from_slice(b"SIT!");
        data.extend_from_slice(&[0, 1]); // 1 file

        let mut entry_header = vec![0u8; 112];
        entry_header[0] = 0; // rsrc method
        entry_header[1] = 0; // data method
        entry_header[2] = 1; // filename length
        entry_header[3] = 0x8E; // MacRoman 'é'

        // Header CRC
        let crc = crc16(&entry_header[0..110]);
        entry_header[110..112].copy_from_slice(&crc.to_be_bytes());

        // Total size
        let total_size: u32 = 22 + 112;
        data.extend_from_slice(&total_size.to_be_bytes());
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&entry_header);

        // Parse and verify
        let archive = SitArchive::parse(&data).expect("Failed to parse MacRoman archive");
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(archive.entries[0].name, "é");
    }
}

// ============================================================================
// External Fixture Tests
// ============================================================================

mod fixtures {
    use super::*;

    /// Test parsing external fixtures (manual_*.sit files)
    ///
    /// These are archives created by external tools for validation.
    #[test]
    fn test_external_fixtures() {
        let fixture_dir = Path::new(FIXTURES_DIR);
        if !fixture_dir.exists() {
            return;
        }

        for entry in fs::read_dir(fixture_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();

            if path.extension().is_some_and(|e| e == "sit")
                && path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("manual_")
            {
                println!("Testing manual fixture: {:?}", path);
                let data = fs::read(&path).unwrap();
                let archive = SitArchive::parse(&data)
                    .unwrap_or_else(|e| panic!("Failed to parse manual fixture {:?}: {}", path, e));
                println!("Parsed {} entries from {:?}", archive.entries.len(), path);
            }
        }
    }
}
// ============================================================================
// CLI Tests
// ============================================================================

mod cli {
    use std::process::Command;

    /// Get path to the compiled binary
    fn get_binary_path() -> std::path::PathBuf {
        let mut path = std::env::current_exe().unwrap();
        path.pop(); // Remove test binary name
        path.pop(); // Remove 'deps'
        path.push("stuffit");
        path
    }

    #[test]
    fn test_list_command_simple() {
        let binary = get_binary_path();

        let output = Command::new(&binary)
            .arg("list")
            .arg("tests/fixtures/test_m13.sit")
            .output()
            .expect("Failed to run list command");

        assert!(
            output.status.success(),
            "Command failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Verify exact output format
        let expected = "\
Archive: tests/fixtures/test_m13.sit
Format: StuffIt 5.0
Entries: 1

hello_m13.txt
Done.
";
        assert_eq!(
            stdout.trim(),
            expected.trim(),
            "Simple list output mismatch"
        );
    }

    #[test]
    fn test_list_command_verbose() {
        let binary = get_binary_path();

        let output = Command::new(&binary)
            .arg("list")
            .arg("tests/fixtures/test_m13.sit")
            .arg("--verbose")
            .output()
            .expect("Failed to run list command");

        assert!(
            output.status.success(),
            "Command failed: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Verify exact output format including table
        let expected = "\
Archive: tests/fixtures/test_m13.sit
Format: StuffIt 5.0
Entries: 1

Name                                               Type     Data       Resource   Modified             Type   Creator
--------------------------------------------------------------------------------------------------------------------
hello_m13.txt                                      File     86*        0*         2015-10-28 16:07:54  TEXT   ttxt  

* = compressed size (use data_ulen/rsrc_ulen for uncompressed)
Done.
";
        assert_eq!(
            stdout.trim(),
            expected.trim(),
            "Verbose list output mismatch"
        );
    }

    /// End-to-end: mtimes survive `archive` then `extract`.
    #[test]
    fn test_archive_extract_preserves_timestamps() {
        use std::time::{Duration, UNIX_EPOCH};

        let binary = get_binary_path();
        let root = std::env::temp_dir().join(format!("stuffit_ts_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let src = root.join("Data");
        std::fs::create_dir_all(src.join("Sub")).unwrap();
        std::fs::write(src.join("file.txt"), b"timestamped").unwrap();
        std::fs::write(src.join("Sub").join("nested.txt"), b"nested").unwrap();

        let file_time = UNIX_EPOCH + Duration::from_secs(999_999_999);
        let nested_time = UNIX_EPOCH + Duration::from_secs(1_234_567_890);
        set_mtime(&src.join("file.txt"), file_time);
        set_mtime(&src.join("Sub").join("nested.txt"), nested_time);

        // Directory mtimes are only set portably on Unix in this test;
        // extraction itself handles directories on all platforms.
        #[cfg(unix)]
        let folder_time = UNIX_EPOCH + Duration::from_secs(888_888_888);
        #[cfg(unix)]
        set_mtime(&src.join("Sub"), folder_time);

        let archive_path = root.join("out.sit");
        let status = Command::new(&binary)
            .arg("archive")
            .arg("-o")
            .arg(&archive_path)
            .arg(&src)
            .status()
            .expect("Failed to run archive command");
        assert!(status.success());

        // The archive itself records the timestamps.
        let data = std::fs::read(&archive_path).unwrap();
        let parsed = stuffit::SitArchive::parse(&data).unwrap();
        let file_entry = parsed
            .entries
            .iter()
            .find(|e| e.name == "Data/file.txt")
            .expect("file entry missing from archive");
        assert_eq!(file_entry.modification_time(), Some(file_time));

        let dst = root.join("extracted");
        let status = Command::new(&binary)
            .arg("extract")
            .arg(&archive_path)
            .arg("-o")
            .arg(&dst)
            .status()
            .expect("Failed to run extract command");
        assert!(status.success());

        let mtime = |p: &std::path::Path| std::fs::metadata(p).unwrap().modified().unwrap();
        assert_eq!(mtime(&dst.join("Data").join("file.txt")), file_time);
        assert_eq!(
            mtime(&dst.join("Data").join("Sub").join("nested.txt")),
            nested_time
        );
        #[cfg(unix)]
        assert_eq!(mtime(&dst.join("Data").join("Sub")), folder_time);

        std::fs::remove_dir_all(&root).unwrap();
    }

    fn set_mtime(path: &std::path::Path, time: std::time::SystemTime) {
        // A read-only handle is enough for futimens on Unix; Windows needs
        // write access (only regular files get their mtime set here).
        #[cfg(unix)]
        let file = std::fs::File::open(path).unwrap();
        #[cfg(not(unix))]
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(time).unwrap();
    }

    #[test]
    fn test_list_command_nonexistent_file() {
        let binary = get_binary_path();

        let output = Command::new(&binary)
            .arg("list")
            .arg("nonexistent.sit")
            .output()
            .expect("Failed to run list command");

        assert!(
            !output.status.success(),
            "Command should fail for nonexistent file"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Error: File not found"));
    }

    #[test]
    fn test_list_command_both_formats() {
        let binary = get_binary_path();

        // Test StuffIt 5.0 format
        let output = Command::new(&binary)
            .arg("list")
            .arg("tests/fixtures/test_m0.sit")
            .output()
            .expect("Failed to run list command");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Format: StuffIt 5.0"));
        assert!(stdout.contains("hello_m0.txt"));
    }

    #[test]
    fn test_list_command_complex_fixture() {
        let binary = get_binary_path();

        let output = Command::new(&binary)
            .arg("list")
            .arg("tests/fixtures/test_complex.sit")
            .output()
            .expect("Failed to run list command");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Verify exact output format
        let expected = "\
Archive: tests/fixtures/test_complex.sit
Format: StuffIt 5.0
Entries: 10

README.txt
config.json
Documents/
Documents/letter.txt
Documents/report.txt
Documents/Archive/
Documents/Archive/old.txt
Images/
Images/photo.jpg
App.rsrc
Done.
";
        assert_eq!(
            stdout.trim(),
            expected.trim(),
            "Complex fixture simple list output mismatch"
        );
    }

    #[test]
    fn test_list_command_complex_fixture_verbose() {
        let binary = get_binary_path();

        let output = Command::new(&binary)
            .arg("list")
            .arg("tests/fixtures/test_complex.sit")
            .arg("--verbose")
            .output()
            .expect("Failed to run list command");

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Verify exact output format including complete table
        // Note: Folders have null bytes (\0) for Type and Creator columns
        let expected = format!(
            "\
Archive: tests/fixtures/test_complex.sit
Format: StuffIt 5.0
Entries: 10

Name                                               Type     Data       Resource   Modified             Type   Creator
--------------------------------------------------------------------------------------------------------------------
README.txt                                         File     89*        0*         2015-10-28 16:07:54  TEXT   ttxt  
config.json                                        File     34*        0*         2015-10-28 16:07:54  TEXT   ttxt  
Documents                                          Folder   0          0          2015-10-28 16:07:54  {}   {}  
Documents/letter.txt                               File     59*        0*         2015-10-28 16:07:54  TEXT   ttxt  
Documents/report.txt                               File     63*        0*         2015-10-28 16:07:54  TEXT   ttxt  
Documents/Archive                                  Folder   0          0          2015-10-28 16:07:54  {}   {}  
Documents/Archive/old.txt                          File     30*        0*         2015-10-28 16:07:54  TEXT   ttxt  
Images                                             Folder   0          0          2015-10-28 16:07:54  {}   {}  
Images/photo.jpg                                   File     4*         0*         2015-10-28 16:07:54  JPEG   prvw  
App.rsrc                                           File     26*        44*        2015-10-28 16:07:54  APPL   TEST  

* = compressed size (use data_ulen/rsrc_ulen for uncompressed)
Done.
",
            "\0\0\0\0", "\0\0\0\0", "\0\0\0\0", "\0\0\0\0", "\0\0\0\0", "\0\0\0\0"
        );
        assert_eq!(
            stdout.trim(),
            expected.trim(),
            "Complex fixture verbose list output mismatch"
        );
    }
}
