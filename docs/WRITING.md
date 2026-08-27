# How to write in this repository

Every comment, every document, every string a person reads.

## Who reads this

Somebody who is good at software and has never worked on an exchange. They have
twenty minutes. They want to know what this does, whether it works, and how it
was checked.

They do not know what a maker is. They do not know what a tick is. They have
never read RFC 9162.

**If they have to look something up to follow a sentence, that sentence failed.**

## The two rules that produce that

**Write so the shape is clear to somebody who knows nothing.** Say the concrete
thing first, then why it matters. Use real numbers and real names from this
system, never invented examples.

**Then cut it to Simplified Technical English.** This is the standard aviation
uses for maintenance manuals, so a mechanic who does not speak English as a
first language cannot misread an instruction. We are not certified against it.
We use its rules:

- One word for one thing. Never change the word for a thing inside a document.
- One idea in a sentence.
- 20 words in a sentence for an instruction. 25 for a description.
- Active voice. `The engine refuses the order`, not `the order is refused`.
- Present tense for what the code does. Past tense for what happened.
- No metaphors. No idioms.
- The simplest word that is exact. Not the shortest, and not the cleverest.

## What must survive the rewrite

Most comments in this repository are good. They say **why**, they carry numbers,
and they name what was rejected. That is the value. Simpler language must not
cost any of it.

**Never delete.**

- A reason. `// clamped, not refused` needs the sentence that says why.
- A number, or where it came from. `423 levels on the live exchange` beats
  `a lot of levels`.
- A limit. Every `what this does not catch` stays.
- A rejected alternative and why it lost.
- A date, a measurement, or the machine a measurement came from. A performance
  number without the machine and the mix is not a measurement. `/tmp` on the
  development host is a tmpfs, so a benchmark that writes there measures memory
  and not disk.

**A shorter comment that lost the argument is a worse comment.** If simplifying
costs a reason, keep the reason and write two sentences.

## The moves that do the work

| instead of | write |
|---|---|
| a long sentence with a clause in the middle | two sentences |
| `it`, `this`, `that` pointing at something three lines up | the name of the thing |
| `we`, `you` | the thing that acts: `the sequencer`, `the checker` |
| `handle`, `manage`, `process` | what it actually does: `refuses`, `counts`, `writes` |
| `simply`, `just`, `obviously`, `of course` | nothing, delete the word |
| `leverage`, `utilise`, `surface` (verb) | `use`, `use`, `show` |
| a word the reader must look up | the word, then a short line saying what it means |

## The whole-tree checks

Apply these rules to every UTF-8 file a person can read. That includes source
comments, browser strings, workflow names, configuration comments, scripts,
and documentation. A file extension is not an excuse to skip text.

- Use sentence case for headings.
- Use straight quotes.
- Do not use U+2013 or U+2014 in authored text. Write a period, comma, `to`, or
  `and` instead.
- Do not decorate headings or bullets with emoji.
- Remove stock introductions, praise, promotional claims, vague sources, and
  generic conclusions.
- Replace a bold label followed by a colon with a sentence. A short bold
  lead-in ending in a period is allowed when the next sentence adds real
  information.
- Keep technical words only when they name a real mechanism or syntax. Cargo's
  `features` key and the literal symbol error `underscore` are not prose.

`services/tests/em_dashes.rs` and `services/tests/unslop.rs` read every UTF-8
file in the tree. The second test exempts this guide because a guide must spell
the words it rejects. Both tests exempt the exact third-party source, generated
records, fixtures, lockfiles, and license named in their source. Protocol fields
and cited publication titles keep their original meaning and syntax. Do not
rewrite provenance to make a style check pass.

## Names

`docs/GLOSSARY.md` is the source. Use the name in its table and no other.

The programs are: the sequencer (`feed.rs`), the exchange (`matcher.rs`), the
separate service (`inbox.rs`), the checker (`verify.rs`), the audit
(`prove.rs`), a validator (`validator.rs`), the bot (`bot.rs`), the anchor
sender (`anchor/`).

`GLOSSARY.md` also has a **Words to avoid** table. A phrase in that table is
banned in code, in documents, and in anything on screen. `services/tests/`
checks it.

## The test to apply to any sentence

Read it out loud. If you run out of breath, it is two sentences.

Ask what a reader must already know to follow it. If the answer is anything
about trading, either say it in the sentence or cut it.

## What this file is not

It is not a rule against precision. `RFC 9162 section 2.1.4.2` is exact and
short, and a reader who needs it can find it. Write the plain sentence first and
put the reference after it.

It is not a rule against long documents. `docs/DECISIONS.md` is long because it
records seventeen decisions with their numbers. That is correct. Every one of
its sentences should still pass the rules above.
