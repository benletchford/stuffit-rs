//! Regenerate `tests/fixtures/windows_icon.sit.bin` for the extraction test.

use stuffit::{SitArchive, SitEntry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = SitArchive::new();
    archive.add_entry(SitEntry {
        name: "Folder".into(),
        is_folder: true,
        ..Default::default()
    });
    archive.add_entry(SitEntry {
        name: "Folder/Icon".into(),
        data_fork: b"icon data".to_vec(),
        resource_fork: b"icon resource".to_vec(),
        ..Default::default()
    });

    let sit = archive.serialize()?;
    let mut header = [0u8; 128];
    let name = b"windows-icon.sit";
    header[1] = name.len() as u8;
    header[2..2 + name.len()].copy_from_slice(name);
    header[65..69].copy_from_slice(b"SIT5");
    header[69..73].copy_from_slice(b"SIT!");
    header[83..87].copy_from_slice(&(sit.len() as u32).to_be_bytes());

    let mut wrapped = header.to_vec();
    wrapped.extend_from_slice(&sit);
    wrapped.resize(128 + sit.len().div_ceil(128) * 128, 0);
    std::fs::write("tests/fixtures/windows_icon.sit.bin", wrapped)?;
    Ok(())
}
