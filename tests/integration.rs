use stuffit::SitArchive;
use stuffit::SitEntry;
use std::fs;
use std::path::Path;

const FIXTURES_DIR: &str = "tests/fixtures";

fn setup() {
    // No-op for read-only tests, but keeping hook if needed
}

#[test]
fn test_write_read_m0_store() {
    let mut archive = SitArchive::new();
    let entry_name = "hello_m0.txt";
    let content = b"Hello World from Method 0 (Store)!".to_vec();

    let entry = SitEntry {
        name: entry_name.to_string(),
        data_fork: content.clone(),
        resource_fork: Vec::new(),
        file_type: [0; 4],
        creator: [0; 4],
        finder_flags: 0,
        is_folder: false,
        data_method: 0,
        rsrc_method: 0,
        data_ulen: 0,
        rsrc_ulen: 0,
    };
    archive.entries.push(entry);

    // Serialize with Method 0
    let data = archive.serialize_with_method(0).expect("Failed to serialize M0");

    // Verify parsing
    let parsed = SitArchive::parse(&data).expect("Failed to parse SIT");
    
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].name, entry_name);
    assert_eq!(parsed.entries[0].data_fork, content);
    assert_eq!(parsed.entries[0].data_method, 0);
}

#[test]
fn test_write_read_m13_compressed() {
    let mut archive = SitArchive::new();
    let entry_name = "hello_m13.txt";
    // Repetitive content to ensure compression happens
    let content = b"Repetitive Repetitive Repetitive Repetitive Repetitive Content generic generic generic".to_vec();

    let entry = SitEntry {
        name: entry_name.to_string(),
        data_fork: content.clone(),
        resource_fork: Vec::new(),
        file_type: [0; 4],
        creator: [0; 4],
        finder_flags: 0,
        is_folder: false,
        data_method: 0,
        rsrc_method: 0,
        data_ulen: 0,
        rsrc_ulen: 0,
    };
    archive.entries.push(entry);

    // Serialize with Method 13 (SIT13)
    let data = archive.serialize_with_method(13).expect("Failed to serialize M13");

    // Verify parsing
    let parsed = SitArchive::parse(&data).expect("Failed to parse SIT");

    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].name, entry_name);
    assert_eq!(parsed.entries[0].data_fork, content);
    // Note: data_method might be 13 (SIT13)
    // If content was too small, it might have fell back to uncompressed? 
    // But our encoder usually forces the method unless we implemented smart fallback.
    // Sit13Encoder always compresses (even if inefficiently).
}

#[test]
fn test_read_external_fixtures() {
    // This test looks for any .sit files in fixtures that start with "manual_"
    // These would be the ones "generated using unar" or other tools by the user 
    // if they provide them.
    
    setup();
    let fixture_dir = Path::new(FIXTURES_DIR);
    if !fixture_dir.exists() {
        return;
    }

    for entry in fs::read_dir(fixture_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "sit") {
             if path.file_name().unwrap().to_string_lossy().starts_with("manual_") {
                 println!("Testing manual fixture: {:?}", path);
                 let data = fs::read(&path).unwrap();
                 let archive = SitArchive::parse(&data);
                 if let Err(e) = archive {
                     panic!("Failed to parse manual fixture {:?}: {}", path, e);
                 }
                 // We can't verify content without knowing it, simpler check is just validity
                 let archive = archive.unwrap();
                 println!("Parsed {} entries from {:?}", archive.entries.len(), path);
             }
        }
    }
}

// --- New Features Tests ---

#[test]
fn test_write_read_method_14_deflate() {
    let mut archive = SitArchive::new();
    
    let original_data = b"Hello, Deflate! This text should be compressed using Method 14.".to_vec();
    let entry = SitEntry {
        name: "test_deflate.txt".to_string(),
        data_fork: original_data.clone(),
        file_type: *b"TEXT",
        creator: *b"ttxt",
        ..Default::default()
    };
    archive.add_entry(entry);

    // This method does not exist yet; implementing it is the goal.
    // We use method 14 (Deflate)
    let serialized = archive.serialize_with_method(14).expect("Failed to serialize with method 14");

    // Check that it's actually compressed (smaller than original + header overhead is tricky for small strings, 
    // but we can check the method byte in the creating logic or just trust round-trip).
    // Actually, for very small strings, deflate might be larger. 
    // But the real test is round-trip.

    // Parse it back
    let parsed = SitArchive::parse(&serialized).expect("Failed to parse generated archive");
    
    assert_eq!(parsed.entries.len(), 1);
    let out_entry = &parsed.entries[0];
    
    assert_eq!(out_entry.name, "test_deflate.txt");
    assert_eq!(out_entry.data_fork, original_data);
    // Ideally check that the method was actually recorded as 14, 
    // but SitEntry.data_method masks it.
    assert_eq!(out_entry.data_method & 0x0F, 14); 
}

// Copy of CRC16 implementation for test fixture construction
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

#[test]
fn test_read_macroman_encoding() {
    // Construct a minimal SIT! Classic archive with a filename containing 0x8E (é in MacRoman)
    
    // Archive Header (22 bytes)
    let mut data = Vec::new();
    data.extend_from_slice(b"SIT!");
    data.extend_from_slice(&[0, 1]); // 1 file
    
    // Total size = 22 (header) + 112 (entry header) = 134 bytes
    // No data content for this test, just header is enough to parse entry name
    let total_size: u32 = 134; 
    data.extend_from_slice(&total_size.to_be_bytes()); // 6-9
    data.extend_from_slice(&[0u8; 12]); // 10-21: padding/signature2
    
    // Entry Header (112 bytes)
    let mut entry_header = vec![0u8; 112];
    
    // 0, 1: methods (0=store)
    entry_header[0] = 0;
    entry_header[1] = 0;
    
    // 2: filename length
    // We want name "é" (MacRoman 0x8E)
    // In UTF-8 "é" is 0xC3 0xA9 (2 bytes). 
    // If treated as MacRoman, 0x8E should become "é".
    // If treated as UTF-8, 0x8E is invalid and becomes replacement char.
    let name_len = 1;
    entry_header[2] = name_len;
    
    // 3-33: filename
    entry_header[3] = 0x8E; // MacRoman 'é'
    
    // Calculate CRC for header (first 110 bytes)
    let crc = crc16(&entry_header[0..110]);
    entry_header[110] = (crc >> 8) as u8;
    entry_header[111] = (crc & 0xFF) as u8;
    
    data.extend_from_slice(&entry_header);
    
    // Parse
    let archive = SitArchive::parse(&data).expect("Failed to parse MacRoman archive");
    
    assert_eq!(archive.entries.len(), 1);
    
    // Check name
    // If support is implemented, this should be "é"
    // If not, it will likely be "" (REPLACEMENT CHARACTER)
    assert_eq!(archive.entries[0].name, "é");
}

#[test]
fn test_write_read_method_15_bwt() {
    let mut archive = SitArchive::new();
    
    // Use repetitive data for good BWT compression
    let original_data = b"ABCABCABCABCABCABCABCABC The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.".to_vec();
    let entry = SitEntry {
        name: "test_bwt.txt".to_string(),
        data_fork: original_data.clone(),
        file_type: *b"TEXT",
        creator: *b"ttxt",
        ..Default::default()
    };
    archive.add_entry(entry);

    // Serialize with Method 15 (BWT/Arsenic)
    let serialized = archive.serialize_with_method(15).expect("Failed to serialize with method 15");

    // Parse it back
    let parsed = SitArchive::parse(&serialized).expect("Failed to parse generated archive");
    
    assert_eq!(parsed.entries.len(), 1);
    let out_entry = &parsed.entries[0];
    
    assert_eq!(out_entry.name, "test_bwt.txt");
    assert_eq!(out_entry.data_fork, original_data);
    assert_eq!(out_entry.data_method & 0x0F, 15); 
}
