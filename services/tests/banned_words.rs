//! The "Words to avoid" table in `docs/GLOSSARY.md`, checked instead of only
//! written down.
//!
//! `docs/GLOSSARY.md` says it is the source for the names this project uses.
//! Nothing read it. "Escape hatch" was written 31 times for the program the
//! table calls the separate service, and the table never stopped one of them,
//! because a rule that is only written down is a rule nobody runs.
//!
//! So this file reads the repository's own source and documents and fails when
//! a banned phrase comes back. `adversarial.rs` reads the release binary the
//! same way to prove a marker string is absent, and `inbox.rs` reads
//! `static/app.js` as text to compare the browser's rounding with its own.
//!
//! # Why the list is hard-coded and not read from the table
//!
//! The table has ten rows. Nine of them are not obeyed yet: "quorum" appears
//! 63 times, "overdue" 95, "durable" 61, and "overdue" is also a field name in
//! the JSON `GET /status` serves, so the prose cannot change alone. A test
//! that read the whole table would fail today on code nobody touched, and a
//! failing test gets deleted rather than fixed.
//!
//! `BANNED` therefore holds only the rows that are clean, and
//! `the_table_still_bans_every_phrase_this_test_enforces` checks each one is
//! still written in the table, so the test and the document cannot drift
//! apart. Clean a row, then add it here.

use std::fs;
use std::path::{Path, PathBuf};

/// The repository root: `services/`'s parent.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("services/ has a parent")
        .to_path_buf()
}

/// The phrases no file below may contain, compared in lower case.
///
/// One row of `docs/GLOSSARY.md`'s "Words to avoid" table, split into the
/// spellings that were actually in the tree: the whole phrase, the hyphenated
/// adjective, and the bare noun the phrase was shortened to.
const BANNED: [&str; 3] = ["escape hatch", "escape-hatch", "the hatch"];

/// Directories never entered. Build output and git objects hold copies of the
/// source, and a copy is not a place anybody writes.
const SKIPPED_DIRS: [&str; 4] = ["target", ".git", "node_modules", "out"];

/// Files exempt from the check, and why. Each entry is a path relative to the
/// repository root.
///
/// - `docs/GLOSSARY.md` states the banned phrase to ban it.
/// - This file lists the phrases to look for them.
const EXEMPT: [&str; 2] = ["docs/GLOSSARY.md", "services/tests/banned_words.rs"];

/// Every file under `dir` this test reads, with the skipped directories left
/// out.
fn files_to_read(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        // A directory that cannot be read is not a place prose hides, and
        // failing here would turn a permissions problem into a naming failure.
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

/// No file writes a phrase the glossary bans.
///
/// The failure names the file, the line number and the line, so the person who
/// wrote it can read the row in `docs/GLOSSARY.md` and write the name instead.
#[test]
fn no_file_writes_a_phrase_the_glossary_bans() {
    let root = repo_root();
    let mut files = Vec::new();
    files_to_read(&root, &mut files);
    assert!(
        files.len() > 100,
        "only {} files were read from {}; the walk found nothing to check",
        files.len(),
        root.display()
    );

    let mut hits = Vec::new();
    for path in &files {
        let relative = path.strip_prefix(&root).unwrap_or(path);
        let relative = relative.to_string_lossy().replace('\\', "/");
        if EXEMPT.contains(&relative.as_str()) {
            continue;
        }
        // Not every file is UTF-8, and one that is not holds no prose.
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            let lowered = line.to_lowercase();
            for phrase in BANNED {
                if lowered.contains(phrase) {
                    hits.push(format!("{}:{}: {}", relative, number + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        hits.is_empty(),
        "{} line(s) write a phrase docs/GLOSSARY.md bans. Write the name from \
         its table instead:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

/// The test and the document cannot drift apart.
///
/// If somebody deletes the row from the table, this fails and says so, rather
/// than leaving a test that enforces a rule the source no longer states.
#[test]
fn the_table_still_bans_every_phrase_this_test_enforces() {
    let table = fs::read_to_string(repo_root().join("docs/GLOSSARY.md"))
        .expect("docs/GLOSSARY.md is readable");
    let lowered = table.to_lowercase();
    assert!(
        lowered.contains("## words to avoid"),
        "docs/GLOSSARY.md has no \"Words to avoid\" table"
    );
    for phrase in BANNED {
        assert!(
            lowered.contains(phrase),
            "this test bans {:?}, but docs/GLOSSARY.md does not say so",
            phrase
        );
    }
}
