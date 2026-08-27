//! The list in `docs/ENGINE.md` section 5, checked instead of only written
//! down.
//!
//! Section 5 names the modules the checker may import. That list is the
//! project's central claim: the checker writes every matching rule a second
//! time, so a disagreement between the checker and the exchange is the
//! evidence. If the checker imports a matching rule, the second copy is not
//! independent and the claim fails.
//!
//! Nothing read the list. It said `merkle` was imported, which it is not, and
//! it did not say `anchor` was, which it is. The rule that matters held: there
//! is no `matcher` import under `verify/`. But a boundary nobody checks is
//! discipline, not a fact.
//!
//! So this file reads `services/src/verify.rs` and every file under
//! `services/src/verify/`, collects every module name written after
//! `crate::`, and fails on a name that is not allowed.
//!
//! # Why the list is a `const` here and not read from the document
//!
//! `docs/ENGINE.md` section 5 is the prose. `ALLOWED` below is the
//! enforcement. `banned_words.rs` states the reason and it holds here too: a
//! test that parses a document fails on the first sentence somebody rewrites,
//! and a failing test gets deleted rather than fixed. Change the document and
//! this `const` together.
//!
//! # Test-only imports are held to the same rule
//!
//! `verify.rs` uses `crate::feed::PAGE_LIMIT` inside `#[cfg(test)]` code, and
//! this file counts it. A test that imports the exchange can make the checker
//! agree with the exchange without anybody seeing it: the held history the
//! checker replays in its own tests is built by that code, so a matching rule
//! imported there would be a matching rule the checker's tests never
//! disagree with. `feed` is therefore on `ALLOWED` and named in section 5,
//! rather than exempt from the walk.

use std::fs;
use std::path::{Path, PathBuf};

/// The modules the checker may name. `docs/ENGINE.md` section 5 is the prose
/// for this list; this `const` is the enforcement. Change both together.
///
/// - `domain`: what a message is, and how a price and a quantity are read.
/// - `logchain`: the running hash chain, and the signature over a head.
/// - `wire`: the message envelope on the network, and the header names.
/// - `reporting`: counts the rows a check read, and prints what failed. It
///   is where the checker reaches `merkle`, which no file here names.
/// - `operator`: the bytes one operator signature covers, and the Ed25519
///   check over them.
/// - `fetch`: how to read a bounded body over HTTP.
/// - `anchor`: how to reach the anchor contract, and how to read `/sth`.
/// - `feed`: one constant, `PAGE_LIMIT`, in test builds only.
/// - `verify`: the checker's own module, written as a full path from a
///   submodule. Not another program.
const ALLOWED: [&str; 9] = [
    "anchor",
    "domain",
    "feed",
    "fetch",
    "logchain",
    "operator",
    "reporting",
    "verify",
    "wire",
];

/// The one name that is not a policy choice. `matcher` holds the six matching
/// steps. The checker exists to disagree with them.
const MATCHER: &str = "matcher";

/// `services/src/`.
fn source_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The checker's files: `verify.rs`, and every `.rs` under `verify/`.
fn checker_files() -> Vec<PathBuf> {
    let src = source_root();
    let mut files = vec![src.join("verify.rs")];
    let entries = fs::read_dir(src.join("verify")).expect("services/src/verify/ is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// One module name the checker wrote, and where.
struct Named {
    file: String,
    line_number: usize,
    line: String,
    module: String,
}

/// Every module name written after `crate::` in the checker's files.
///
/// The text is read for `crate::`, not for `use` lines only: `verify.rs:1376`
/// calls `crate::anchor::fetch_tree_head` inline with no `use`, and a walk
/// over `use` lines alone would miss it.
///
/// `use super::` is not read. It reaches the checker's own parent module, not
/// another program.
///
/// A line that starts with `//` is skipped. Those lines are prose about the
/// rule. `verify/operator_key.rs` explains which module it imports and why.
/// A comment names no import. A comment after code on the same line is
/// still read, because the code before it is real.
fn names_written(files: &[PathBuf]) -> Vec<Named> {
    let mut found = Vec::new();
    for path in files {
        let text = fs::read_to_string(path).expect("a checker file is readable");
        let file = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for (at, _) in line.match_indices("crate::") {
                let rest = &line[at + "crate::".len()..];
                let module: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if module.is_empty() {
                    continue;
                }
                found.push(Named {
                    file: file.clone(),
                    line_number: index + 1,
                    line: line.trim().to_string(),
                    module,
                });
            }
        }
    }
    found
}

/// The checker imports no module outside the list.
///
/// The failure names the file, the line number and the line, so the person who
/// wrote it can either take the import out or add the module to `ALLOWED` and
/// to `docs/ENGINE.md` section 5.
#[test]
fn the_checker_imports_only_the_modules_engine_md_allows() {
    let files = checker_files();
    assert!(
        files.len() >= 6,
        "only {} checker file(s) were read; the walk found nothing to check",
        files.len()
    );

    let names = names_written(&files);
    assert!(
        names.len() > 20,
        "only {} module name(s) were read from {} file(s); the walk read no code",
        names.len(),
        files.len()
    );

    let outside: Vec<String> = names
        .iter()
        .filter(|named| !ALLOWED.contains(&named.module.as_str()))
        .map(|named| {
            format!(
                "{}:{}: crate::{}, {}",
                named.file, named.line_number, named.module, named.line
            )
        })
        .collect();

    assert!(
        outside.is_empty(),
        "{} line(s) in the checker name a module docs/ENGINE.md section 5 does \
         not allow. The checker writes every matching rule a second time, so \
         it may only import what carries no rule. Take the import out, or add \
         the module to ALLOWED here and to section 5, with the reason it \
         carries no rule:\n{}",
        outside.len(),
        outside.join("\n")
    );
}

/// The checker never names `matcher`.
///
/// This is the one import that is not a policy choice, so it has its own test
/// and its own sentence.
#[test]
fn the_checker_never_names_the_matcher() {
    let files = checker_files();
    let hits: Vec<String> = names_written(&files)
        .iter()
        .filter(|named| named.module == MATCHER)
        .map(|named| format!("{}:{}: {}", named.file, named.line_number, named.line))
        .collect();

    assert!(
        hits.is_empty(),
        "{} line(s) in the checker name crate::{}. The checker stopped being \
         an independent implementation, and this project's claim no longer \
         holds: a checker that calls the same matching code as the exchange \
         agrees with every bug in it, so a passing run proves nothing. Write \
         the rule a second time in verify/ instead:\n{}",
        hits.len(),
        MATCHER,
        hits.join("\n")
    );
}
