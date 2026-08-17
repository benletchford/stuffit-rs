//! Decode every entry of a StuffIt archive; print bytes, a content hash, and time.
//! Usage: cargo run --release --example decode_all -- <archive.sit> [repeat]
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Instant;
use stuffit::SitArchive;

fn main() {
    let path = std::env::args().nth(1).expect("archive path");
    let repeat: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let bytes = std::fs::read(&path).expect("read archive");
    let archive = SitArchive::parse(&bytes).expect("parse");
    let mut best = f64::MAX;
    let mut hash = 0u64;
    let mut total = 0usize;
    for _ in 0..repeat {
        let start = Instant::now();
        let mut hasher = DefaultHasher::new();
        total = 0;
        for entry in &archive.entries {
            if entry.is_folder {
                continue;
            }
            let (data, rsrc) = entry.decompressed_forks().expect("decode");
            total += data.len() + rsrc.len();
            entry.name.hash(&mut hasher);
            data.hash(&mut hasher);
            rsrc.hash(&mut hasher);
        }
        hash = hasher.finish();
        best = best.min(start.elapsed().as_secs_f64());
    }
    println!(
        "entries={} decoded_bytes={} hash={:016x} best_of_{}={:.3}s",
        archive.entries.len(),
        total,
        hash,
        repeat,
        best
    );
}
