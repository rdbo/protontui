//! protontui: a terminal client for Proton VPN that connects the whole host through WireGuard.
//!
//! The binary (`main.rs`) is a thin `clap` front end over this library. Module layout follows PLAN.md §3.

pub mod api;
pub mod config;
pub mod daemon;
pub mod ipc;
pub mod logging;
pub mod servers;
pub mod session;
pub mod tui;
pub mod vpn;
