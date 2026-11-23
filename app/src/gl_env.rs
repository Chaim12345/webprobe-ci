//! Choose a renderer path that works on this machine before any window or GL
//! code runs.
//!
//! Root cause of "the window never appears" on WSL2 (found 2026-11-15 with a
//! controlled run matrix on Xvfb: Mesa 26.1.6, winit 0.30, glutin 0.32):
//!
//! 1. `LIBGL_ALWAYS_INDIRECT=1` (typically left in a shell rc from the VcXsrv-on-
//!    Windows era) forces indirect GLX. X.Org, Xvfb and Xwayland ship with
//!    indirect GLX disabled, so the direct FBConfig glutin asks for is rejected:
//!    `GLXBadFBConfig`.
//! 2. WSL2 exposes `/dev/dxg`, not a DRM render node. Without one, Mesa's hardware
//!    path falls through to zink and dies with `ZINK: failed to choose pdev` /
//!    `egl: failed to create dri2 screen`, so glutin gets no config at all. WSLg's
//!    weston has no GBM interfaces either, so winit's Wayland-first choice is a
//!    dead end as well.
//!
//! The UI is flat 2-D, so llvmpipe through X11/GLX is more than enough. With no
//! render node we ask Mesa for software rendering and make winit take X11: winit
//! 0.30 picks Wayland whenever `WAYLAND_DISPLAY` is set, and the old
//! `WINIT_UNIX_BACKEND` switch no longer exists. Anything the user set explicitly
//! wins, and `WEBPROBE_GL=native` skips every edit.

/// Environment edits to make before the window is created.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub unset: Vec<&'static str>,
    pub set: Vec<(&'static str, &'static str)>,
}

/// Decide the edits. Pure, so the policy is testable without touching the real
/// process environment or `/dev`.
pub fn plan(has_render_node: bool, env: impl Fn(&str) -> Option<String>) -> Plan {
    let mut plan = Plan::default();
    if env("WEBPROBE_GL").as_deref() == Some("native") {
        return plan;
    }
    let is_set = |name: &str| env(name).is_some_and(|value| !value.is_empty());

    // glutin only ever asks for direct contexts, so this can never help.
    if env("LIBGL_ALWAYS_INDIRECT").is_some() {
        plan.unset.push("LIBGL_ALWAYS_INDIRECT");
    }

    if !has_render_node {
        if !is_set("LIBGL_ALWAYS_SOFTWARE") {
            plan.set.push(("LIBGL_ALWAYS_SOFTWARE", "1"));
        }
        // Only leave Wayland when X11 is actually there to fall back to.
        if is_set("DISPLAY") {
            for name in ["WAYLAND_DISPLAY", "WAYLAND_SOCKET"] {
                if is_set(name) {
                    plan.unset.push(name);
                }
            }
        }
    }
    plan
}

/// Apply the plan to this process. Call first thing in `main`, before any thread
/// exists: editing the environment is not thread safe.
pub fn apply() {
    let plan = plan(has_render_node(), |name| std::env::var(name).ok());
    for name in &plan.unset {
        std::env::remove_var(name);
    }
    for (name, value) in &plan.set {
        std::env::set_var(name, value);
    }
    if !plan.unset.is_empty() || !plan.set.is_empty() {
        eprintln!(
            "webprobe: renderer environment adjusted (unset {:?}, set {:?}); WEBPROBE_GL=native disables this",
            plan.unset, plan.set
        );
    }
}

/// Second chance for the render-node guess. A node can exist and still be
/// unusable from the X server the window lands on (seen 2026-11-17: a kernel
/// that exposes `/dev/dri/renderD128` under WSL, and Xvfb, which has no DRI;
/// Mesa falls through to zink and glutin fails with "provided native window
/// is not supported"). The edits for one software retry: exactly the
/// no-render-node plan, plus a guard so it happens once. `None` when the user
/// chose the GL path, software GL was already in use, or this is the retry.
pub fn software_retry(env: impl Fn(&str) -> Option<String>) -> Option<Plan> {
    if env("WEBPROBE_GL").as_deref() == Some("native")
        || env("WEBPROBE_GL_RETRY").is_some()
        || env("LIBGL_ALWAYS_SOFTWARE").is_some_and(|v| !v.is_empty())
    {
        return None;
    }
    let mut plan = plan(false, env);
    plan.set.push(("WEBPROBE_GL_RETRY", "1"));
    Some(plan)
}

/// Replace this process with a fresh copy on software GL, when
/// [`software_retry`] allows it. Returns only if it does not apply or the exec
/// failed. Sockets and files are close-on-exec, so the new copy rebinds the
/// proxy listener; the caller removes its session marker first.
#[cfg(unix)]
pub fn reexec_with_software_gl() {
    use std::os::unix::process::CommandExt;
    let Some(plan) = software_retry(|name| std::env::var(name).ok()) else {
        return;
    };
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    eprintln!("webprobe: the window could not be created on hardware GL; restarting once with software GL (set {:?})", plan.set);
    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    for name in &plan.unset {
        cmd.env_remove(name);
    }
    for (name, value) in &plan.set {
        cmd.env(name, value);
    }
    let err = cmd.exec();
    eprintln!("webprobe: restart failed: {err}");
}

#[cfg(not(unix))]
pub fn reexec_with_software_gl() {}

#[cfg(target_os = "linux")]
fn has_render_node() -> bool {
    std::fs::read_dir("/dev/dri")
        .map(|dir| {
            dir.flatten()
                .any(|entry| entry.file_name().to_string_lossy().starts_with("renderD"))
        })
        .unwrap_or(false)
}

/// Other platforms have their own GL stack: leave it alone.
#[cfg(not(target_os = "linux"))]
fn has_render_node() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn unusable_render_node_gets_one_software_retry() {
        let p = software_retry(env(&[("DISPLAY", ":97"), ("WAYLAND_DISPLAY", "wayland-0")]))
            .expect("retry");
        assert_eq!(
            p.set,
            vec![("LIBGL_ALWAYS_SOFTWARE", "1"), ("WEBPROBE_GL_RETRY", "1")]
        );
        assert_eq!(p.unset, vec!["WAYLAND_DISPLAY"]);
        assert!(
            software_retry(env(&[("WEBPROBE_GL_RETRY", "1")])).is_none(),
            "only once"
        );
        assert!(
            software_retry(env(&[("LIBGL_ALWAYS_SOFTWARE", "1")])).is_none(),
            "already software"
        );
        assert!(
            software_retry(env(&[("WEBPROBE_GL", "native")])).is_none(),
            "user's choice"
        );
    }

    #[test]
    fn indirect_glx_is_always_dropped() {
        for render_node in [true, false] {
            let p = plan(render_node, env(&[("LIBGL_ALWAYS_INDIRECT", "1")]));
            assert!(
                p.unset.contains(&"LIBGL_ALWAYS_INDIRECT"),
                "render node = {render_node}"
            );
        }
    }

    #[test]
    fn wsl_shape_gets_software_gl_and_x11() {
        // The exact environment that broke the window: WSLg plus a stale indirect flag.
        let p = plan(
            false,
            env(&[
                ("DISPLAY", ":0"),
                ("WAYLAND_DISPLAY", "wayland-0"),
                ("LIBGL_ALWAYS_INDIRECT", "1"),
            ]),
        );
        assert_eq!(p.set, vec![("LIBGL_ALWAYS_SOFTWARE", "1")]);
        assert_eq!(p.unset, vec!["LIBGL_ALWAYS_INDIRECT", "WAYLAND_DISPLAY"]);
    }

    #[test]
    fn a_render_node_keeps_the_hardware_path() {
        let p = plan(
            true,
            env(&[("DISPLAY", ":0"), ("WAYLAND_DISPLAY", "wayland-0")]),
        );
        assert_eq!(p, Plan::default());
    }

    #[test]
    fn wayland_only_session_is_not_pushed_onto_x11() {
        let p = plan(false, env(&[("WAYLAND_DISPLAY", "wayland-0")]));
        assert!(p.unset.is_empty());
        assert_eq!(p.set, vec![("LIBGL_ALWAYS_SOFTWARE", "1")]);
    }

    #[test]
    fn explicit_user_choice_wins() {
        let p = plan(
            false,
            env(&[("LIBGL_ALWAYS_SOFTWARE", "0"), ("DISPLAY", ":0")]),
        );
        assert!(
            p.set.is_empty(),
            "an explicit LIBGL_ALWAYS_SOFTWARE must not be overridden"
        );
    }

    #[test]
    fn native_opt_out_skips_every_edit() {
        let p = plan(
            false,
            env(&[
                ("WEBPROBE_GL", "native"),
                ("LIBGL_ALWAYS_INDIRECT", "1"),
                ("DISPLAY", ":0"),
            ]),
        );
        assert_eq!(p, Plan::default());
    }
}
