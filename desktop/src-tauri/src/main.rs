#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sidecar;

use sidecar::{SidecarConfig, SidecarHandle};
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

fn main() {
    let mut cfg = SidecarConfig::default();
    if let Ok(bin) = env::var("RAKSA_BIN") {
        if !bin.trim().is_empty() {
            cfg.raksa_bin = bin;
        }
    }
    if let Ok(ws) = env::var("RAKSA_WORKSPACE") {
        if !ws.trim().is_empty() {
            cfg.workspace = ws;
        }
    }
    cfg.from_reports = env::var("RAKSA_FROM_REPORTS").ok();
    cfg.siem_url = env::var("RAKSA_SIEM_URL").ok();

    let mut handle = SidecarHandle::spawn(&cfg).expect("failed to launch raksa ui sidecar");
    handle
        .wait_ready(Duration::from_secs(15))
        .expect("raksa ui sidecar did not become ready in time");

    let launch_url: tauri::Url = handle
        .launch_url()
        .parse()
        .expect("invalid sidecar bootstrap URL");
    let shared_sidecar = Arc::new(Mutex::new(Some(handle)));
    let cleanup_ref = Arc::clone(&shared_sidecar);

    let app = tauri::Builder::default()
        .setup(move |app| {
            let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::External(launch_url))
                .title("Raksa Defense Workbench")
                .inner_size(1440.0, 900.0)
                .min_inner_size(1024.0, 680.0)
                .build()?;
            let _ = win.set_focus();
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building Raksa Desktop Tauri application");

    app.run(move |_app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            if let Ok(mut guard) = cleanup_ref.lock() {
                let _ = guard.take();
            }
        }
    });
}
