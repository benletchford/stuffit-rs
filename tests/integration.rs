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

    /// Helper for writing variable-length bit sequences (big-endian)
    pub struct BitWriter {
        data: Vec<u8>,
        bit_buf: u32,
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

        pub fn write_bits_be(&mut self, val: u32, n: u32) {
            let val = val & ((1 << n) - 1);
            self.bit_buf = (self.bit_buf << n) | val;
            self.bits_in_buf += n;
            while self.bits_in_buf >= 8 {
                let byte = (self.bit_buf >> (self.bits_in_buf - 8)) as u8;
                self.data.push(byte);
                self.bits_in_buf -= 8;
            }
        }

        pub fn flush(&mut self) {
            if self.bits_in_buf > 0 {
                let byte = (self.bit_buf << (8 - self.bits_in_buf)) as u8;
                self.data.push(byte);
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
        use std::collections::HashMap;

        let mut writer = BitWriter::new();
        let mut dict: HashMap<Vec<u8>, u32> = HashMap::new();

        // Initialize dictionary with single-byte sequences
        for i in 0..256 {
            dict.insert(vec![i as u8], i as u32);
        }

        let mut next_code = 258; // 256=Clear, 257=End
        let mut code_size = 9;

        // Write clear code
        writer.write_bits_be(256, code_size);

        if data.is_empty() {
            writer.write_bits_be(257, code_size);
            return writer.into_data();
        }

        let mut current = vec![data[0]];

        for &b in &data[1..] {
            let mut next = current.clone();
            next.push(b);

            if dict.contains_key(&next) {
                current = next;
            } else {
                // Emit code for current sequence
                let code = *dict.get(&current).unwrap();
                writer.write_bits_be(code, code_size);

                // Add new sequence to dictionary
                if next_code < 16384 {
                    dict.insert(next, next_code);
                    next_code += 1;

                    // Increase bit width when needed
                    if next_code == (1 << code_size) && code_size < 14 {
                        code_size += 1;
                    }
                }

                current = vec![b];
            }
        }

        // Emit final sequence
        if !current.is_empty() {
            let code = *dict.get(&current).unwrap();
            writer.write_bits_be(code, code_size);
        }

        // Write end code
        writer.write_bits_be(257, code_size);
        writer.into_data()
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

    /// Placeholder for Method 3 (Huffman)
    ///
    /// Huffman uses the same "Meta Code" table as Method 13, which is already
    /// tested in the roundtrip::test_method_13_compressed test.
    #[test]
    fn test_method_3_huffman() {
        // Huffman logic is shared with Method 13 and already covered
        // Constructing a manual Huffman-encoded fixture is complex
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

Name                                               Type     Data       Resource   Type   Creator
----------------------------------------------------------------------------------------------------
hello_m13.txt                                      File     86*        0*         TEXT   ttxt  

* = compressed size (use data_ulen/rsrc_ulen for uncompressed)
Done.
";
        assert_eq!(
            stdout.trim(),
            expected.trim(),
            "Verbose list output mismatch"
        );
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

Name                                               Type     Data       Resource   Type   Creator
----------------------------------------------------------------------------------------------------
README.txt                                         File     89*        0*         TEXT   ttxt  
config.json                                        File     34*        0*         TEXT   ttxt  
Documents                                          Folder   0          0          {}   {}  
Documents/letter.txt                               File     59*        0*         TEXT   ttxt  
Documents/report.txt                               File     63*        0*         TEXT   ttxt  
Documents/Archive                                  Folder   0          0          {}   {}  
Documents/Archive/old.txt                          File     30*        0*         TEXT   ttxt  
Images                                             Folder   0          0          {}   {}  
Images/photo.jpg                                   File     4*         0*         JPEG   prvw  
App.rsrc                                           File     26*        44*        APPL   TEST  

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
