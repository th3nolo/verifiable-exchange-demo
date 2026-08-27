//! Dash punctuation, checked across every authored UTF-8 file in the repository.
//!
//! The writing guide asks for a period, comma, or a word such as `to` or `and`
//! instead of dash punctuation. This test checks both Unicode characters that
//! can hide the same sentence break.
//!
//! # Why the characters use code-point escapes
//!
//! A test that spells a banned character must exempt itself. Code-point
//! escapes keep the test under the same rule as every other file.
//!
//! # Why the walk reads every file
//!
//! Text appears in source, documentation, configuration, scripts, fixtures,
//! and browser strings. Extension lists miss one as soon as a new file type
//! arrives. The walk therefore tries every file as UTF-8 and skips only build
//! output, dependency trees, Git data, and files that are not UTF-8. Exact
//! third-party and generated text is read and counted but keeps its source
//! punctuation.

use std::fs;
use std::path::{Path, PathBuf};

/// The repository root: `services/`'s parent.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("services/ has a parent")
        .to_path_buf()
}

/// The banned punctuation, named without writing either character.
const DASHES: [(char, &str); 2] = [('\u{2013}', "U+2013"), ('\u{2014}', "U+2014")];

/// Directories never entered. They contain copies, dependencies, or Git data.
const SKIPPED_DIRS: [&str; 4] = ["target", ".git", "node_modules", "out"];

/// Exact text whose bytes or provenance matter more than house style.
const PROVENANCE_EXEMPT: [&str; 7] = [
    "LICENSE",
    "anchor/ExchangeAnchor.json",
    "anchor/ExchangeRootAnchor.json",
    "anchor/go.sum",
    "services/Cargo.lock",
    "services/src/testdata/live-500.ndjson",
    "services/static/ed25519.js",
];

/// Every file under `dir`, except files inside skipped directories.
fn files_to_read(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !SKIPPED_DIRS.contains(&name.as_ref()) {
                files_to_read(&path, found);
            }
            continue;
        }
        if name != ".git" {
            found.push(path);
        }
    }
}

#[test]
fn no_text_file_writes_dash_punctuation() {
    let root = repo_root();
    let mut files = Vec::new();
    files_to_read(&root, &mut files);

    let mut text_files = 0usize;
    let mut checked_files = 0usize;
    let mut hits = Vec::new();
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        text_files += 1;
        let relative = path.strip_prefix(&root).unwrap_or(path);
        let relative = relative.to_string_lossy().replace('\\', "/");
        if PROVENANCE_EXEMPT.contains(&relative.as_str()) {
            continue;
        }
        checked_files += 1;
        for (number, line) in text.lines().enumerate() {
            for (character, code_point) in DASHES {
                if line.contains(character) {
                    hits.push(format!(
                        "{}:{} ({code_point}): {}",
                        relative,
                        number + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        text_files > 100,
        "only {text_files} UTF-8 files were read from {}; the walk found too little to check",
        root.display()
    );
    assert!(
        checked_files > 100,
        "only {checked_files} authored UTF-8 files were checked; the exemptions are too broad"
    );
    assert!(
        hits.is_empty(),
        "{} line(s) use dash punctuation. Use a period, comma, `to`, or `and`:\n{}",
        hits.len(),
        hits.join("\n")
    );
}
