//! Tests for `webprobe_support::util` that need core-only modules
//! (`crawl` for a real browser binary). Split from util.rs in Stage A (#37).

#[cfg(test)]
mod tests {
    fn alive_with(marker: &str) -> usize {
        std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
            .filter(|p| *p != std::process::id())
            .filter(|p| {
                let c = std::fs::read(format!("/proc/{p}/cmdline")).unwrap_or_default();
                let st = std::fs::read_to_string(format!("/proc/{p}/stat")).unwrap_or_default();
                String::from_utf8_lossy(&c).contains(marker) && !st.contains(") Z ")
            })
            .count()
    }

    /// The real leak: a killed browser left its zygotes and renderers
    /// running (about 70 processes each). Every one must be gone.
    #[test]
    fn a_headless_browser_leaves_no_processes_behind() {
        let Some(bin) = crate::crawl::chromium_binary() else {
            return;
        };
        let profile = std::env::temp_dir().join(format!("wp-tree-browser-{}", std::process::id()));
        let mut cmd = std::process::Command::new(bin);
        cmd.args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            &format!("--user-data-dir={}", profile.display()),
            "about:blank",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
        crate::util::own_process_group(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let marker = profile.display().to_string();
        // Helpers appear within a second on an idle box but can take much
        // longer under build load; poll, and kill before asserting so a slow
        // start cannot leave the browser running (it did, 2026-11-17).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut helpers = alive_with(&marker);
        while helpers <= 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(250));
            helpers = alive_with(&marker);
        }
        crate::util::kill_process_tree(
            child.id(),
            Some(&marker),
            std::time::Duration::from_secs(2),
        );
        assert!(helpers > 1, "browser should have spawned helpers");
        let _ = child.wait();
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(alive_with(&marker), 0, "no browser process may survive");
        let _ = std::fs::remove_dir_all(&profile);
    }
}
