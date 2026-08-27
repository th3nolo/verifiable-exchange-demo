//! Objective writing checks for every authored UTF-8 file in the repository.
//!
//! Tone and sentence quality still need review by a person. This test covers
//! the parts a byte scan can judge without guessing: stock phrases, plain-word
//! substitutions, curly quotes, and decorative emoji in headings or bullets.
//!
//! `docs/WRITING.md` states several rejected phrases as examples. This file
//! lists the same phrases so it can find them. Exact third-party and generated
//! files are read and counted, but their source text is not rewritten to fit
//! this repository's voice.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("services/ has a parent")
        .to_path_buf()
}

const SKIPPED_DIRS: [&str; 4] = ["target", ".git", "node_modules", "out"];
const RULE_EXEMPT: [&str; 2] = ["docs/WRITING.md", "services/tests/unslop.rs"];
const PROVENANCE_EXEMPT: [&str; 7] = [
    "LICENSE",
    "anchor/ExchangeAnchor.json",
    "anchor/ExchangeRootAnchor.json",
    "anchor/go.sum",
    "services/Cargo.lock",
    "services/src/testdata/live-500.ndjson",
    "services/static/ed25519.js",
];

const BANNED_PHRASES: [&str; 33] = [
    "pivotal moment",
    "testament to",
    "evolving landscape",
    "setting the stage for",
    "indelible mark",
    "deeply rooted",
    "experts believe",
    "industry reports suggest",
    "some critics argue",
    "despite the challenges",
    "continues to thrive",
    "serves as",
    "stands as",
    "i hope this helps",
    "let me know if",
    "of course!",
    "certainly!",
    "found the smoking gun",
    "while specific details are limited",
    "great question",
    "you're absolutely right",
    "in order to",
    "due to the fact that",
    "it is important to note that",
    "could potentially",
    "potentially possibly",
    "possibly be argued",
    "might potentially",
    "the future looks bright",
    "in the event that",
    "gold-plating",
    "north star",
    "api surface",
];

const BANNED_WORDS: [&str; 43] = [
    "additionally",
    "crucial",
    "delve",
    "enduring",
    "enhance",
    "fostering",
    "garner",
    "interplay",
    "intricate",
    "pivotal",
    "showcase",
    "tapestry",
    "testament",
    "vibrant",
    "nestled",
    "breathtaking",
    "groundbreaking",
    "highlighting",
    "ensuring",
    "reflecting",
    "showcasing",
    "renowned",
    "stunning",
    "must-visit",
    "substrate",
    "wedge",
    "locus",
    "vantage",
    "nexus",
    "bedrock",
    "scaffolding",
    "modality",
    "paradigm",
    "endgame",
    "flywheel",
    "landscape",
    "ratchet",
    "evacuate",
    "utilize",
    "utilise",
    "leverage",
    "facilitate",
    "numerous",
];

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

fn contains_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(start, matched)| {
        let before = text[..start].chars().next_back();
        let after = text[start + matched.len()..].chars().next();
        let is_word = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
        before.is_none_or(|ch| !is_word(ch)) && after.is_none_or(|ch| !is_word(ch))
    })
}

fn has_decorative_emoji(line: &str) -> bool {
    let mut prose = line.trim_start();
    for prefix in ["//!", "///", "//", "#"] {
        if let Some(rest) = prose.strip_prefix(prefix) {
            prose = rest.trim_start();
            break;
        }
    }
    let is_heading_or_bullet = prose.starts_with('#')
        || prose.starts_with("- ")
        || prose.starts_with("* ")
        || prose.starts_with("+ ");
    is_heading_or_bullet
        && prose.chars().any(|ch| {
            matches!(
                ch as u32,
                0x1F300..=0x1F5FF
                    | 0x1F600..=0x1F64F
                    | 0x1F680..=0x1F6FF
                    | 0x1F900..=0x1F9FF
                    | 0x1FA70..=0x1FAFF
            )
        })
}

#[test]
fn objective_writing_patterns_stay_out_of_every_text_file() {
    let root = repo_root();
    let mut files = Vec::new();
    files_to_read(&root, &mut files);

    let curly_quotes = ['\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}'];
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
        if RULE_EXEMPT.contains(&relative.as_str())
            || PROVENANCE_EXEMPT.contains(&relative.as_str())
        {
            continue;
        }
        checked_files += 1;

        for (number, line) in text.lines().enumerate() {
            let lowered = line.to_ascii_lowercase();
            for phrase in BANNED_PHRASES {
                if lowered.contains(phrase) {
                    hits.push(format!(
                        "{}:{} banned phrase {:?}: {}",
                        relative,
                        number + 1,
                        phrase,
                        line.trim()
                    ));
                }
            }
            for word in BANNED_WORDS {
                if contains_word(&lowered, word) {
                    hits.push(format!(
                        "{}:{} banned word {:?}: {}",
                        relative,
                        number + 1,
                        word,
                        line.trim()
                    ));
                }
            }
            for opening in ["not just", "not only"] {
                if let Some(start) = lowered.find(opening) {
                    if lowered[start + opening.len()..].contains(" but ") {
                        hits.push(format!(
                            "{}:{} uses the formula {:?} ... but: {}",
                            relative,
                            number + 1,
                            opening,
                            line.trim()
                        ));
                    }
                }
            }
            if line.chars().any(|ch| curly_quotes.contains(&ch)) {
                hits.push(format!(
                    "{}:{} uses a curly quote: {}",
                    relative,
                    number + 1,
                    line.trim()
                ));
            }
            if has_decorative_emoji(line) {
                hits.push(format!(
                    "{}:{} uses decorative emoji: {}",
                    relative,
                    number + 1,
                    line.trim()
                ));
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
        "{} objective writing issue(s) found:\n{}",
        hits.len(),
        hits.join("\n")
    );
}
