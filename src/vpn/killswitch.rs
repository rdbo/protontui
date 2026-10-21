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
