//! Cargo Bay updates for Panoptic: the host trait the desktop app implements, and the one
//! "Panoptic Updates" window that links the app with a code, checks for a signed update, shows the
//! download and offers Restart now. This crate needs no network or file code: the app hands over an
//! [`UpdateHost`] ([`crate::LightcraftApp::set_update_host`]) and the UI reads its [`UpdateView`] and
//! asks it to link, check or restart. Ported from Euclidean's `cargo_bay.rs` and `updates.rs` (one window
//! instead of a dialog and a window).

use serde_json::Value;

use crate::LightcraftApp;

/// The status line when the updater is off.
pub const OFF: &str = "Updates are off in this copy.";

/// What the desktop app does for the updater. Implemented in `apps/lightcraft`.
pub trait UpdateHost {
    /// A cheap snapshot, called every frame.
    fn view(&self) -> UpdateView;
    /// Start a background claim with a link code; the result shows in [`Self::view`].
    fn link(&mut self, code: &str);
    /// Start a background check (and stage the update on a Mac).
    fn check(&mut self);
    /// Remember to relaunch once this process quits.
    fn restart(&mut self);
}

/// What the UI shows of the updater.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UpdateView {
    pub linked: bool,
    /// A link or a check is running.
    pub busy: bool,
    /// The latest English message (already filled).
    pub message: Option<String>,
    /// Bumps each time `message` is set.
    pub message_seq: u64,
    /// A staged version waiting for Restart now.
    pub ready: Option<String>,
    /// The last link attempt's English error.
    pub link_error: Option<String>,
    /// The version running now.
    pub installed: String,
    /// The new version, once a check has heard of one.
    pub offered: Option<String>,
    /// Release notes of `offered`, if any.
    pub notes: Option<String>,
    /// Bytes downloaded so far.
    pub received: u64,
    /// The download's size; 0 before an offer is heard.
    pub total: u64,
    /// The download is done and is being checked.
    pub verifying: bool,
    /// The last check found nothing newer.
    pub up_to_date: bool,
    /// The English line for the last check's error.
    pub error: Option<String>,
    /// A newer version this platform cannot install by itself.
    pub elsewhere: Option<String>,
}

/// The window's state: the host and what the window remembers between frames.
#[derive(Default)]
pub(crate) struct Runtime {
    host: Option<Box<dyn UpdateHost>>,
    /// The window is open.
    pub(crate) open: bool,
    /// What is typed in the link-code field.
    code: String,
    /// The first-run offer (unlinked) or the ready notice has been considered this run.
    offered: bool,
    ready_shown: bool,
    was_unlinked: bool,
}

impl LightcraftApp {
    /// Hand the app the Cargo Bay updater (the desktop app does, unless updates are off in this run).
    pub fn set_update_host(&mut self, host: Box<dyn UpdateHost>) {
        self.cargo_bay.host = Some(host);
    }
}

/// What the window shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpdateState {
    NotLinked,
    Ready,
    Checking,
    Verifying,
    Downloading,
    Elsewhere,
    Error,
    UpToDate,
}

/// The state for a view. `mac` is whether this platform downloads updates itself.
pub(crate) fn state(v: &UpdateView, mac: bool) -> UpdateState {
    if !v.linked {
        UpdateState::NotLinked
    } else if v.ready.is_some() && !v.busy {
        UpdateState::Ready
    } else if v.busy && (v.offered.is_none() || !mac) {
        UpdateState::Checking
    } else if v.busy && v.verifying {
        UpdateState::Verifying
    } else if v.busy {
        UpdateState::Downloading
    } else if v.elsewhere.is_some() {
        UpdateState::Elsewhere
    } else if v.error.is_some() {
        UpdateState::Error
    } else if v.up_to_date {
        UpdateState::UpToDate
    } else {
        UpdateState::Checking
    }
}

/// Megabytes (1,000,000 bytes, one decimal) for the progress line.
fn megabytes(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1_000_000.0)
}

/// What is typed, as `XXXX-XXXX`: letters and digits only, upper case, at most eight, dashed after
/// the fourth. For display; the uplink crate validates the code.
fn shown(typed: &str) -> String {
    let clean: String = typed.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).take(8).collect();
    if clean.len() > 4 { format!("{}-{}", &clean[..4], &clean[4..]) } else { clean }
}

/// Help ▸ Check for Updates…: start a check and open the window, or say updates are off.
pub(crate) fn check(app: &mut LightcraftApp) -> Result<Value, String> {
    let Some(host) = app.cargo_bay.host.as_mut() else { return Err(OFF.into()) };
    // A version already staged shows its Restart now; asking again would only flash "Checking".
    let v = host.view();
    if !(v.ready.is_some() && !v.busy) && v.linked {
        host.check();
    }
    app.cargo_bay.open = true;
    Ok(Value::Null)
}

/// Help ▸ Link to Cargo Bay…: open the window (its first state is the code field).
pub(crate) fn open_link(app: &mut LightcraftApp) -> Result<Value, String> {
    if app.cargo_bay.host.is_none() {
        return Err(OFF.into());
    }
    app.cargo_bay.open = true;
    Ok(Value::Null)
}

/// Once a frame: the first time the app runs unlinked, or with an update ready, open the window.
pub(crate) fn tick(app: &mut LightcraftApp, ctx: &egui::Context) {
    let rt = &mut app.cargo_bay;
    let Some(host) = rt.host.as_ref() else { return };
    let v = host.view();
    if v.busy {
        ctx.request_repaint_after(std::time::Duration::from_millis(80));
    }
    if !rt.offered && !app.ui.quit {
        if !v.linked {
            rt.offered = true;
            rt.open = true;
        } else if v.ready.is_some() && !v.busy && !rt.ready_shown {
            rt.offered = true;
            rt.ready_shown = true;
            rt.open = true;
        }
    }
    // Linked from this window: check straight away.
    let just_linked = rt.was_unlinked && v.linked && !v.busy && v.ready.is_none();
    rt.was_unlinked = !v.linked;
    if just_linked && let Some(host) = rt.host.as_mut() {
        host.check();
        ctx.request_repaint();
    }
}

/// Restart now: the host remembers to relaunch, then the app quits as Quit does.
fn restart(app: &mut LightcraftApp) {
    if let Some(host) = app.cargo_bay.host.as_mut() {
        host.restart();
    }
    app.cargo_bay.open = false;
    app.ui.quit = true;
}

enum Act {
    Link,
    Restart,
    Retry,
    Close,
}

/// Draw the window while it is open.
pub(crate) fn show(app: &mut LightcraftApp, ctx: &egui::Context) {
    if !app.cargo_bay.open {
        return;
    }
    let Some(v) = app.cargo_bay.host.as_ref().map(|h| h.view()) else {
        app.cargo_bay.open = false;
        return;
    };
    let st = state(&v, cfg!(target_os = "macos"));
    let new = v.offered.clone().or_else(|| v.elsewhere.clone()).unwrap_or_default();
    let mut open = true;
    let mut act = None;
    let mut code = app.cargo_bay.code.clone();
    egui::Window::new(crate::i18n::tr("Panoptic Updates"))
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .pivot(egui::Align2::CENTER_CENTER)
        .default_pos(ctx.content_rect().center())
        .show(ctx, |ui| {
            ui.set_width(380.0);
            let busy_line = |ui: &mut egui::Ui, text: String| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label(text);
                });
            };
            let offer = |ui: &mut egui::Ui| {
                ui.label(egui::RichText::new(format!("Panoptic {new} is available (you have {}).", v.installed)).strong());
                if let Some(notes) = v.notes.as_deref().filter(|n| !n.trim().is_empty()) {
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical().max_height(120.0).auto_shrink([false, true]).show(ui, |ui| {
                        ui.label(egui::RichText::new(notes).size(11.5).weak());
                    });
                }
                ui.add_space(8.0);
            };
            match st {
                UpdateState::NotLinked => {
                    ui.label("Type the link code from your Tools page on the Mothership so Panoptic can update itself.");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Link code");
                        let edit = egui::TextEdit::singleline(&mut code).hint_text("XXXX-XXXX").desired_width(110.0).font(egui::TextStyle::Monospace);
                        ui.add_enabled(!v.busy, edit);
                        code = shown(&code);
                    });
                    if v.busy {
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("Linking…").weak());
                    } else if let Some(e) = &v.link_error {
                        ui.add_space(6.0);
                        ui.colored_label(ui.visuals().error_fg_color, e);
                    }
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!v.busy && !code.trim().is_empty(), egui::Button::new("Link")).clicked() {
                            act = Some(Act::Link);
                        }
                        if ui.button("Later").clicked() {
                            act = Some(Act::Close);
                        }
                    });
                }
                UpdateState::Ready => {
                    ui.label(format!("Panoptic {} is ready.", v.ready.as_deref().unwrap_or_default()));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Restart now").clicked() {
                            act = Some(Act::Restart);
                        }
                        if ui.button("Later").clicked() {
                            act = Some(Act::Close);
                        }
                    });
                }
                UpdateState::Checking => busy_line(ui, "Checking for updates…".into()),
                UpdateState::Verifying => busy_line(ui, "Checking the download…".into()),
                UpdateState::Downloading => {
                    offer(ui);
                    let frac = if v.total == 0 { 0.0 } else { (v.received as f32 / v.total as f32).clamp(0.0, 1.0) };
                    ui.add(egui::ProgressBar::new(frac).desired_width(380.0));
                    ui.label(egui::RichText::new(format!("{} of {} MB", megabytes(v.received), megabytes(v.total))).size(11.0).weak());
                }
                UpdateState::Elsewhere => {
                    offer(ui);
                    ui.label(format!("{new} is available — download it from the Mothership's Tools page"));
                    ui.add_space(10.0);
                    if ui.button("Close").clicked() {
                        act = Some(Act::Close);
                    }
                }
                UpdateState::Error => {
                    ui.colored_label(ui.visuals().error_fg_color, v.error.as_deref().unwrap_or_default());
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Try again").clicked() {
                            act = Some(Act::Retry);
                        }
                        if ui.button("Close").clicked() {
                            act = Some(Act::Close);
                        }
                    });
                }
                UpdateState::UpToDate => {
                    ui.label(format!("Panoptic {} is up to date.", v.installed));
                    ui.add_space(10.0);
                    if ui.button("Close").clicked() {
                        act = Some(Act::Close);
                    }
                }
            }
        });
    app.cargo_bay.code = code.clone();
    app.cargo_bay.open = open;
    match act {
        Some(Act::Link) => {
            if let Some(host) = app.cargo_bay.host.as_mut() {
                host.link(&code);
            }
        }
        Some(Act::Restart) => restart(app),
        Some(Act::Retry) => {
            if let Some(host) = app.cargo_bay.host.as_mut() {
                host.check();
            }
        }
        Some(Act::Close) => app.cargo_bay.open = false,
        None => {}
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    #[derive(Default)]
    pub(crate) struct Calls {
        pub(crate) links: Vec<String>,
        pub(crate) checks: usize,
        pub(crate) restarts: usize,
    }

    #[derive(Clone, Default)]
    pub(crate) struct FakeHost {
        pub(crate) view: Rc<RefCell<UpdateView>>,
        pub(crate) calls: Rc<RefCell<Calls>>,
    }

    impl UpdateHost for FakeHost {
        fn view(&self) -> UpdateView {
            self.view.borrow().clone()
        }
        fn link(&mut self, code: &str) {
            self.calls.borrow_mut().links.push(code.to_string());
        }
        fn check(&mut self) {
            self.calls.borrow_mut().checks += 1;
        }
        fn restart(&mut self) {
            self.calls.borrow_mut().restarts += 1;
        }
    }

    fn linked() -> UpdateView {
        UpdateView { linked: true, installed: "0.1.0".into(), ..Default::default() }
    }

    fn app_with(host: Option<FakeHost>) -> LightcraftApp {
        let mut app = LightcraftApp::new(lightcraft_engine::Session::new(), Default::default());
        if let Some(h) = host {
            app.set_update_host(Box::new(h));
        }
        app
    }

    fn frame(app: &mut LightcraftApp, ctx: &egui::Context) {
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            tick(app, ui.ctx());
            show(app, ui.ctx());
        });
        out.textures_delta.clear();
    }

    #[test]
    fn state_follows_the_view() {
        let mut v = UpdateView::default();
        assert_eq!(state(&v, true), UpdateState::NotLinked);
        v.linked = true;
        v.up_to_date = true;
        assert_eq!(state(&v, true), UpdateState::UpToDate);
        v.ready = Some("0.1.1".into());
        assert_eq!(state(&v, true), UpdateState::Ready);
        v.ready = None;
        v.busy = true;
        assert_eq!(state(&v, true), UpdateState::Checking);
        v.offered = Some("0.1.1".into());
        assert_eq!(state(&v, true), UpdateState::Downloading);
        v.verifying = true;
        assert_eq!(state(&v, true), UpdateState::Verifying);
        v = linked();
        v.error = Some("x".into());
        assert_eq!(state(&v, true), UpdateState::Error);
    }

    #[test]
    fn typed_code_is_shown_dashed_and_upper_case() {
        assert_eq!(shown("ab"), "AB");
        assert_eq!(shown("abcd-ef"), "ABCD-EF");
        assert_eq!(shown(" ab cd efgh12 "), "ABCD-EFGH");
    }

    #[test]
    fn no_updater_says_off_and_calls_nothing() {
        let mut app = app_with(None);
        assert_eq!(check(&mut app), Err(OFF.to_string()));
        assert_eq!(open_link(&mut app), Err(OFF.to_string()));
        let ctx = egui::Context::default();
        frame(&mut app, &ctx);
        assert!(!app.cargo_bay.open);
    }

    #[test]
    fn unlinked_start_opens_the_window_once_and_later_closes_it() {
        let host = FakeHost::default();
        let mut app = app_with(Some(host.clone()));
        let ctx = egui::Context::default();
        frame(&mut app, &ctx);
        assert!(app.cargo_bay.open, "offered at start");
        app.cargo_bay.open = false; // Later
        frame(&mut app, &ctx);
        assert!(!app.cargo_bay.open, "not offered again this run");
        assert!(host.calls.borrow().links.is_empty());
        assert!(open_link(&mut app).is_ok());
        assert!(app.cargo_bay.open, "the Help command still opens it");
    }

    #[test]
    fn check_calls_host_once_and_a_ready_update_is_not_asked_again() {
        let host = FakeHost::default();
        *host.view.borrow_mut() = linked();
        let mut app = app_with(Some(host.clone()));
        assert!(check(&mut app).is_ok());
        assert_eq!(host.calls.borrow().checks, 1);
        assert!(app.cargo_bay.open);
        let ctx = egui::Context::default();
        frame(&mut app, &ctx);
        frame(&mut app, &ctx);
        assert_eq!(host.calls.borrow().checks, 1, "a frame never checks by itself");
        host.view.borrow_mut().ready = Some("0.1.1".into());
        check(&mut app).unwrap();
        assert_eq!(host.calls.borrow().checks, 1, "a staged version shows Restart now instead");
    }

    #[test]
    fn ready_opens_the_window_and_restart_asks_host_then_quits() {
        let host = FakeHost::default();
        *host.view.borrow_mut() = UpdateView { ready: Some("0.1.1".into()), ..linked() };
        let mut app = app_with(Some(host.clone()));
        let ctx = egui::Context::default();
        frame(&mut app, &ctx);
        assert!(app.cargo_bay.open);
        restart(&mut app);
        assert_eq!(host.calls.borrow().restarts, 1);
        assert!(app.ui.quit);
        assert!(!app.cargo_bay.open);
    }

    #[test]
    fn linking_checks_straight_away() {
        let host = FakeHost::default();
        let mut app = app_with(Some(host.clone()));
        let ctx = egui::Context::default();
        frame(&mut app, &ctx);
        assert_eq!(host.calls.borrow().checks, 0);
        host.view.borrow_mut().linked = true;
        frame(&mut app, &ctx);
        assert_eq!(host.calls.borrow().checks, 1);
        frame(&mut app, &ctx);
        assert_eq!(host.calls.borrow().checks, 1);
    }
}
