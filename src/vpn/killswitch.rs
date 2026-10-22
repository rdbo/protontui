//! nftables kill switch (T3.6).
//!
//! All rules live in tables whose names start with [`TABLE_PREFIX`] (the main `inet protontui` table, and the
//! separate IPv6 leak-protection table), so cleanup is one `delete table` each.

use std::io;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

/// The main kill switch table, in family `inet`.
pub const TABLE: &str = "protontui";
/// Every nftables table protontui creates starts with this, whatever its family.
pub const TABLE_PREFIX: &str = "protontui";

/// Applies an nftables script atomically (`nft -f -`). `Ok(false)` when there's no `nft` binary.
pub async fn nft_apply(script: &str) -> Result<bool> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut child = match Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).context("running nft"),
    };
    let mut stdin = child.stdin.take().context("nft stdin")?;
    stdin.write_all(script.as_bytes()).await?;
    drop(stdin);
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        bail!("nft -f: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(true)
}

/// Deletes one table if it exists.
pub async fn delete_table(family: &str, name: &str) -> Result<()> {
    // `destroy` would be idempotent but needs nft ≥ 1.0.8; create-then-delete works everywhere.
    nft_apply(&format!("table {family} {name} {{}}\ndelete table {family} {name}\n")).await.map(drop)
}

/// Deletes every nftables table protontui created.
pub async fn recover() -> Result<Vec<String>> {
    let output = match Command::new("nft").args(["list", "tables"]).output().await {
        Ok(output) => output,
        // No nft binary means no kill switch could have been installed.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("running nft"),
    };
    if !output.status.success() {
        bail!("nft list tables: {}", String::from_utf8_lossy(&output.stderr).trim());
    }

    let mut actions = Vec::new();
    for (family, name) in our_tables(&String::from_utf8_lossy(&output.stdout)) {
        let status = Command::new("nft").args(["delete", "table", family, name]).status().await?;
        if !status.success() {
            bail!("nft delete table {family} {name} failed ({status})");
        }
        actions.push(format!("deleted nftables table {family} {name}"));
    }
    Ok(actions)
}

/// Picks `(family, name)` of our tables out of `nft list tables` output (`table inet protontui` per line).
fn our_tables(listing: &str) -> Vec<(&str, &str)> {
    listing
        .lines()
        .filter_map(|line| match line.split_whitespace().collect::<Vec<_>>()[..] {
            ["table", family, name] if name.starts_with(TABLE_PREFIX) => Some((family, name)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_only_our_tables() {
        let listing = "table inet filter\ntable inet protontui\ntable ip6 protontui6\ntable ip nat\n";
        assert_eq!(our_tables(listing), vec![("inet", "protontui"), ("ip6", "protontui6")]);
        assert!(our_tables("").is_empty());
    }
}
