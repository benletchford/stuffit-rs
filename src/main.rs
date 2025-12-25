use clap::Parser;
use rayon::prelude::*;
use stuffit::{SitArchive, SitEntry};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Parser, Debug)]
#[command(name = "stuffit")]
#[command(version, about = "StuffIt (.sit) utility for Kestrel", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Extract a StuffIt (.sit) file
    Extract {
        /// Path to the StuffIt (.sit) file
        input: String,

        /// Output directory (defaults to current directory)
        #[arg(short, long)]
        output: Option<String>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Create a new StuffIt (.sit) file
    Archive {
        /// Path to the output StuffIt (.sit) file
        #[arg(short, long)]
        output: String,

        /// List of files/directories to include
        inputs: Vec<String>,

        /// Compression method (0=none, 13=compressed)
        #[arg(short, long, default_value = "13")]
        method: u8,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::Extract {
            input,
            output,
            verbose,
        } => {
            let input_path = Path::new(&input);
            if !input_path.exists() {
                eprintln!("Error: File not found: {}", input);
                std::process::exit(1);
            }

            let data = fs::read(input_path)?;
            if verbose {
                println!("Reading {} ({} bytes)...", input, data.len());
            }

            let archive = SitArchive::parse(&data)?;
            let output_base = output
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));

            if !output_base.exists() {
                fs::create_dir_all(&output_base)?;
            }

            println!("Unarchiving {} entries...", archive.entries.len());

            // First pass: create all directories sequentially (must happen before files)
            for entry in &archive.entries {
                if entry.is_folder {
                    extract_entry(&output_base, entry, verbose)
                        .map_err(|e| -> Box<dyn std::error::Error> { e })?;
                }
            }

            // Second pass: extract files in parallel
            let errors = AtomicUsize::new(0);
            archive.entries.par_iter().for_each(|entry| {
                if !entry.is_folder {
                    if let Err(e) = extract_entry(&output_base, entry, verbose) {
                        eprintln!("Error extracting {}: {}", entry.name, e);
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

            if errors.load(Ordering::Relaxed) > 0 {
                eprintln!("Warning: {} files failed to extract", errors.load(Ordering::Relaxed));
            }
        }
        Commands::Archive {
            output,
            inputs,
            method,
            verbose,
        } => {
            let mut archive = SitArchive::new();

            for input in inputs {
                let path = Path::new(&input);
                if !path.exists() {
                    eprintln!("Warning: Input not found: {}", input);
                    continue;
                }

                add_to_archive(&mut archive, path, "", method, verbose)?;
            }

            let data = if method == 0 {
                archive.serialize()?
            } else {
                archive.serialize_compressed()?
            };
            fs::write(&output, data)?;
            let compression_str = if method == 0 {
                "uncompressed"
            } else {
                "compressed"
            };
            println!(
                "Archived {} entries ({}) to {}.",
                archive.entries.len(),
                compression_str,
                output
            );
        }
    }

    println!("Done.");
    Ok(())
}

fn add_to_archive(
    archive: &mut SitArchive,
    path: &Path,
    prefix: &str,
    method: u8,
    verbose: bool,
) -> std::io::Result<()> {
    let name = path.file_name().unwrap().to_string_lossy();
    let full_name = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", prefix, name)
    };

    if path.is_dir() {
        if verbose {
            println!("  Adding folder: {}", full_name);
        }

        // Read folder metadata (FinderInfo) on macOS
        #[cfg(target_os = "macos")]
        let finder_flags = {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
            let attr_c = CString::new("com.apple.FinderInfo").unwrap();
            let mut info = [0u8; 32];
            unsafe {
                let res = libc::getxattr(
                    path_c.as_ptr(),
                    attr_c.as_ptr(),
                    info.as_mut_ptr() as *mut libc::c_void,
                    32,
                    0,
                    0,
                );
                if res >= 10 {
                    u16::from_be_bytes([info[8], info[9]])
                } else {
                    0
                }
            }
        };
        #[cfg(not(target_os = "macos"))]
        let finder_flags = 0u16;

        let entry = SitEntry {
            name: full_name.clone(),
            is_folder: true,
            finder_flags,
            ..Default::default()
        };

        archive.add_entry(entry);

        for result in fs::read_dir(path)? {
            let entry = result?;
            add_to_archive(archive, &entry.path(), &full_name, method, verbose)?;
        }
    } else {
        if verbose {
            println!("  Adding file: {} (method={})", full_name, method);
        }

        let data_fork = fs::read(path)?;

        // Try to read resource fork and metadata if on macOS
        #[cfg(target_os = "macos")]
        let (resource_fork, file_type, creator, finder_flags) = {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;

            let rsrc = fs::read(path.join("..namedfork/rsrc")).unwrap_or_default();

            let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
            let attr_c = CString::new("com.apple.FinderInfo").unwrap();
            let mut info = [0u8; 32];
            let mut ft = [0u8; 4];
            let mut cr = [0u8; 4];
            let mut flags = 0u16;

            unsafe {
                let res = libc::getxattr(
                    path_c.as_ptr(),
                    attr_c.as_ptr(),
                    info.as_mut_ptr() as *mut libc::c_void,
                    32,
                    0,
                    0,
                );
                if res >= 10 {
                    ft.copy_from_slice(&info[0..4]);
                    cr.copy_from_slice(&info[4..8]);
                    flags = u16::from_be_bytes([info[8], info[9]]);
                }
            }

            (rsrc, ft, cr, flags)
        };

        #[cfg(not(target_os = "macos"))]
        let (resource_fork, file_type, creator, finder_flags) =
            (Vec::new(), [0u8; 4], [0u8; 4], 0u16);

        let entry = SitEntry {
            name: full_name,
            data_fork,
            resource_fork,
            file_type,
            creator,
            finder_flags,
            data_method: method,
            rsrc_method: method,
            ..Default::default()
        };

        archive.add_entry(entry);
    }
    Ok(())
}

fn extract_entry(base: &Path, entry: &SitEntry, verbose: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut name = entry.name.clone();

    // Handle special "Icon" file used for folder icons in Classic Mac OS
    // In archives it's often named "Icon", but on disk it must be "Icon\r"
    if name.ends_with("/Icon") || name == "Icon" {
        name.push('\r');
    }

    let path = base.join(&name);

    if entry.is_folder {
        if verbose {
            println!("  Folder: {}", entry.name);
        }
        fs::create_dir_all(&path)?;

        // Set folder metadata
        #[cfg(target_os = "macos")]
        {
            let mut info = [0u8; 32];
            // Finder flags for folder are at offset 8-9
            info[8..10].copy_from_slice(&entry.finder_flags.to_be_bytes());

            apply_finder_info(&path, &info);
        }
    } else {
        // Decompress the forks (this is where parallel work happens)
        let (data_fork, resource_fork) = entry.decompressed_forks()?;
        
        if verbose {
            println!(
                "  File: {} (data: {} bytes, rsrc: {} bytes, type: {:?}, creator: {:?}, flags: 0x{:04x})",
                entry.name,
                data_fork.len(),
                resource_fork.len(),
                String::from_utf8_lossy(&entry.file_type),
                String::from_utf8_lossy(&entry.creator),
                entry.finder_flags
            );
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;

            // If this is an Icon\r file, set the "Has Custom Icon" flag on the parent folder
            if name.ends_with("/Icon\r") || name == "Icon\r" {
                #[cfg(target_os = "macos")]
                {
                    set_custom_icon_flag(parent);
                }
            }
        }

        // Write data fork
        if !data_fork.is_empty() {
            let mut file = fs::File::create(&path)?;
            file.write_all(&data_fork)?;
        } else {
            fs::File::create(&path)?;
        }

        // Write resource fork and metadata
        #[cfg(target_os = "macos")]
        {
            if !resource_fork.is_empty() {
                let rsrc_path = path.join("..namedfork/rsrc");
                let _ = fs::write(&rsrc_path, &resource_fork);
            }

            let mut info = [0u8; 32];
            info[0..4].copy_from_slice(&entry.file_type);
            info[4..8].copy_from_slice(&entry.creator);
            info[8..10].copy_from_slice(&entry.finder_flags.to_be_bytes());

            apply_finder_info(&path, &info);
        }

        #[cfg(not(target_os = "macos"))]
        {
            if !resource_fork.is_empty() {
                let mut raw_rsrc_path = path.clone();
                let mut filename = raw_rsrc_path.file_name().unwrap().to_os_string();
                filename.push(".rsrc");
                raw_rsrc_path.set_file_name(filename);

                let mut rsrc_file = fs::File::create(&raw_rsrc_path)?;
                rsrc_file.write_all(&resource_fork)?;
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_finder_info(path: &Path, info: &[u8; 32]) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
    let attr_c = CString::new("com.apple.FinderInfo").unwrap();

    unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            attr_c.as_ptr(),
            info.as_ptr() as *const libc::c_void,
            32,
            0,
            0,
        );
    }
}

#[cfg(target_os = "macos")]
fn set_custom_icon_flag(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
    let attr_c = CString::new("com.apple.FinderInfo").unwrap();

    let mut info = [0u8; 32];
    unsafe {
        let res = libc::getxattr(
            path_c.as_ptr(),
            attr_c.as_ptr(),
            info.as_mut_ptr() as *mut libc::c_void,
            32,
            0,
            0,
        );
        if res >= 10 {
            // Set bit 10 (0x0400) in big-endian flags at offset 8-9
            info[8] |= 0x04;
            libc::setxattr(
                path_c.as_ptr(),
                attr_c.as_ptr(),
                info.as_ptr() as *const libc::c_void,
                32,
                0,
                0,
            );
        } else {
            // Initialize new FinderInfo with custom icon flag
            info[8] = 0x04;
            libc::setxattr(
                path_c.as_ptr(),
                attr_c.as_ptr(),
                info.as_ptr() as *const libc::c_void,
                32,
                0,
                0,
            );
        }
    }
}
