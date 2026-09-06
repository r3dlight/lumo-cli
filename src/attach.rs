// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading text/document attachments and formatting them as prompt context.
//!
//! Only textual files are supported here; each is size-capped and rejected if it
//! looks binary. The result is a single block that is prepended to the user's
//! message, so the model sees the files as context. (Image attachments would
//! need the multimodal content-parts wire form and are not handled yet.)

use std::path::Path;

use anyhow::{Context, Result, bail};

/// Per-file cap. Attachments share the model's context window, so keep them
/// modest; larger files should be narrowed with `search`/`read_file` instead.
const MAX_ATTACH_BYTES: u64 = 128 * 1024;

/// Read the given paths and format them into one context block, or `None` if
/// the list is empty. Fails if any file is unreadable, too large, or binary:
/// attachments are explicit, so a silent drop would be worse than an error.
pub fn build_block(paths: &[String]) -> Result<Option<String>> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut out = String::from(
        "The user attached the following files as context. Use them to answer; \
         do not repeat their full contents back.\n",
    );
    for p in paths {
        let path = Path::new(p);
        let meta =
            std::fs::metadata(path).with_context(|| format!("cannot access attachment {p}"))?;
        if meta.len() > MAX_ATTACH_BYTES {
            bail!(
                "attachment {p} is {} bytes, over the {} KiB limit; narrow it with search/read_file",
                meta.len(),
                MAX_ATTACH_BYTES / 1024
            );
        }
        let bytes = std::fs::read(path).with_context(|| format!("cannot read attachment {p}"))?;
        if looks_binary(&bytes) {
            bail!("attachment {p} looks binary; only text/document files are supported");
        }
        let content = String::from_utf8_lossy(&bytes);
        let lines = content.lines().count();
        out.push_str(&format!("\n===== {p} ({lines} lines) =====\n"));
        out.push_str(&content);
        if !content.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("===== end =====\n");
    }
    Ok(Some(out))
}

/// Heuristic: a NUL byte in the first 8 KiB marks the file as binary.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}

/// Prepend an attachment block (if any) to a user message.
pub fn prepend(block: &Option<String>, message: &str) -> String {
    match block {
        Some(b) => format!("{b}\nUser request:\n{message}"),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_none() {
        assert!(build_block(&[]).unwrap().is_none());
    }

    #[test]
    fn text_file_is_embedded_and_binary_rejected() {
        let dir = std::env::temp_dir().join(format!("lumo_attach_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let txt = dir.join("note.txt");
        std::fs::write(&txt, "hello\nworld\n").unwrap();
        let block = build_block(&[txt.to_string_lossy().into()])
            .unwrap()
            .unwrap();
        assert!(block.contains("note.txt (2 lines)"));
        assert!(block.contains("hello"));

        let bin = dir.join("blob.bin");
        std::fs::write(&bin, [0u8, 1, 2, 3]).unwrap();
        assert!(build_block(&[bin.to_string_lossy().into()]).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prepend_wraps_message() {
        let b = Some("FILES".to_string());
        assert!(prepend(&b, "do it").contains("FILES"));
        assert!(prepend(&b, "do it").contains("do it"));
        assert_eq!(prepend(&None, "x"), "x");
    }
}
