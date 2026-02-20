use std::env;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use regex::bytes::Regex;

struct CryptoPattern {
    name: &'static str,
    pattern: Vec<u8>,
}

impl CryptoPattern {
    fn new(name: &'static str, pattern: Vec<u8>) -> Self {
        Self { name, pattern }
    }

    fn matches(&self, content: &[u8]) -> bool {
        content.windows(self.pattern.len())
            .any(|window| window == self.pattern.as_slice())
    }
}

fn get_crypto_patterns() -> Vec<CryptoPattern> {
    vec![
        CryptoPattern::new("AES", vec![0x63, 0x7c, 0x77, 0x7b]),
        CryptoPattern::new("BLOWFISH", vec![0xd1, 0x31, 0x0b, 0xa6]),
        CryptoPattern::new("ChaCha20", b"expand 32-byte k".to_vec()),
        CryptoPattern::new("curve25519", vec![
            0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9,
            0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
            0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0,
            0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21
        ]),
        CryptoPattern::new("DES", vec![0x80, 0x10, 0x80, 0x20]),
        CryptoPattern::new("MD5", vec![0xd7, 0x6a, 0xa4, 0x78]),
        CryptoPattern::new("RIPEMD", vec![0xE9, 0x76, 0x6d, 0x7a]),
        CryptoPattern::new("SHA1", vec![0x5a, 0x82, 0x79, 0x99]),
        CryptoPattern::new("SHA256", vec![0xd8, 0x9e, 0x05, 0xc1]),
        CryptoPattern::new("SHA512", vec![0xa2, 0x4d, 0x54, 0x19, 0xc8, 0x37, 0x3d, 0x8c]),
        CryptoPattern::new("SHA3", vec![0x89, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]),
        CryptoPattern::new("SIPHASH", b"uespemos".to_vec()),
        CryptoPattern::new("WHIRLPOOL", vec![0x18, 0x18, 0x60, 0x18, 0xc0, 0x78, 0x30, 0xd8]),
    ]
}

fn scan_file<'a>(path: &PathBuf, patterns: &'a [CryptoPattern]) -> Option<Vec<&'a str>> {
    let mut file = fs::File::open(path).ok()?;
    let mut content = Vec::new();
    file.read_to_end(&mut content).ok()?;

    let mut found = Vec::new();
    for pattern in patterns {
        if pattern.matches(&content) {
            found.push(pattern.name);
        }
    }

    if found.is_empty() {
        None
    } else {
        Some(found)
    }
}

fn scan_path_executables() -> Vec<PathBuf> {
    let path_var = match env::var("PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Warning: PATH variable not found");
            return Vec::new();
        }
    };

    let mut executables = Vec::new();
    
    for dir in env::split_paths(&path_var) {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(metadata) = entry.metadata() {
                            let permissions = metadata.permissions();
                            if permissions.mode() & 0o111 != 0 {
                                executables.push(path);
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        executables.push(path);
                    }
                }
            }
        }
    }
    
    executables
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let patterns = get_crypto_patterns();

    println!("{:<50}\t{}", "File", "Primitives");
    println!("{:<50}\t{}", "====", "==========");

    let files_to_scan: Vec<PathBuf> = if args.len() > 1 {
        // User provided files/directories
        let mut files = Vec::new();
        for arg in &args[1..] {
            let path = PathBuf::from(arg);
            if path.is_dir() {
                if let Ok(entries) = fs::read_dir(&path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() {
                            files.push(p);
                        }
                    }
                }
            } else if path.is_file() {
                files.push(path);
            }
        }
        files
    } else {
        // No arguments: scan PATH executables
        scan_path_executables()
    };

    for file in files_to_scan {
        if let Some(found_primitives) = scan_file(&file, &patterns) {
            let file_str = file.to_string_lossy();
            print!("{:<50}\t", file_str);
            for primitive in found_primitives {
                print!("{} ", primitive);
            }
            println!();
        }
    }
}