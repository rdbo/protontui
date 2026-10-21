//! WireGuard interface create/configure/teardown, handshake and stats polling (T3.2).

use anyhow::Result;
use futures::TryStreamExt;
use rtnetlink::Handle;

/// The tunnel interface protontui owns.
pub const INTERFACE: &str = "proton0";

const ENODEV: i32 = 19;

/// Deletes the [`INTERFACE`] link if it exists.
pub async fn recover(handle: &Handle) -> Result<Vec<String>> {
    let Some(index) = link_index(handle, INTERFACE).await? else {
        return Ok(Vec::new());
    };
    handle.link().del(index).execute().await?;
    Ok(vec![format!("deleted link {INTERFACE}")])
}

/// The index of the link called `name`, or `None` when there's no such link.
pub async fn link_index(handle: &Handle, name: &str) -> Result<Option<u32>> {
    match handle.link().get().match_name(name).execute().try_next().await {
        Ok(link) => Ok(link.map(|l| l.header.index)),
        Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -ENODEV => Ok(None),
        Err(e) => Err(e.into()),
    }
}
