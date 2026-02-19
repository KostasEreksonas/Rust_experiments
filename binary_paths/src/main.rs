use std::env;
use std::fs;
use std::io;
// use std::path::Path;

fn main() -> io::Result<()> {
    // Get PATH as an OsString (handles non-UTF-8 correctly)
    let paths = match env::var_os("PATH") {
        Some(p) => p,
        None => {
            eprintln!("PATH is not set");
            return Ok(());
        }
    };

    // Split PATH into components in an OS-aware way
    for dir in env::split_paths(&paths) {
        println!("=== {} ===", dir.display());

        // Try to read the directory; skip if it fails
        match fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries {
                    if let Ok(entry) = entry {
                        if let Some(name) = entry.file_name().to_str() {
                            println!("{name}");
                        } else {
                            // Fallback for non-UTF-8 names
                            println!("{:?}", entry.file_name());
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("  [could not read {}: {}]", dir.display(), err);
            }
        }

        println!(); // blank line between dirs
    }

    Ok(())
}
