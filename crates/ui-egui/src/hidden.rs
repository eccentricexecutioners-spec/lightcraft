//! What Panoptic hides from the interface, in one place.
//!
//! Hidden means not drawn and not reachable by menu or shortcut; the code, the engine commands and
//! the control channel are untouched, so a feature is cut from the screen without being deleted.
//! The Panoptic app turns the clean screen on at start ([`enable_clean`]); `PANOPTIC_SHOW_ALL=1`
//! in its environment draws everything again (to compare with the full app). Anything else that
//! links this crate (the tests, the CLI, the web build) never calls it and keeps the full app.

use std::sync::atomic::{AtomicBool, Ordering};

/// One thing hidden from the UI, for the record (`_WORKFLOW/app-panoptic/investigations/B1-hidden.md`).
pub struct Entry {
    pub name: &'static str,
    pub was: &'static str,
    pub why: &'static str,
    pub restore: &'static str,
}

const SWITCH: &str = "`PANOPTIC_SHOW_ALL=1`";

macro_rules! entry {
    ($name:expr, $was:expr, $why:expr) => {
        Entry { name: $name, was: $was, why: $why, restore: SWITCH }
    };
}

pub const TABLE: &[Entry] = &[
    entry!(
        "Library pane (My Photos)",
        "`docking.rs` `Panel::Library`, `panels/left.rs`",
        "Photographers know where their files are; Open photo is the way in"
    ),
    entry!(
        "Grid, square grid, Compare, Survey, Reference, People views",
        "`state/view.rs` `ViewMode`, `docking.rs` canvas switch",
        "One photo at a time; the folder strip flips between shots"
    ),
    entry!(
        "Filter bar and top-bar search/filter",
        "`panels/filterbar.rs`, `panels/topbar.rs`",
        "Library search has nothing to search in a hidden library"
    ),
    entry!("Bottom bar (grid size, counts)", "`panels/bottombar.rs`", "Belongs to the grid"),
    entry!(
        "Library chooser at launch and Settings ▸ At launch ▸ Ask",
        "`panels/library_problem.rs` `launch_plan`",
        "The library is hidden; the app opens its own without asking"
    ),
    entry!("Empty-library screen", "`panels/empty_library.rs`", "Replaced by the Open photo prompt"),
    entry!("Demo photos in a new library", "`apps/lightcraft/src/main.rs` seed", "A hidden library starts empty"),
    entry!(
        "File menu: everything except Open photo/folder, Export, Export Previous, preset import/export, Settings, Quit",
        "`menus.rs` `menu_entries`",
        "Library, import, catalog, sync, rename, cull, slideshow, print and backup are file management"
    ),
    entry!("Photo menu: Stack, Rename, Assisted Culling, Tracklog", "`menus.rs` `menu_entries`", "Library organising"),
    entry!(
        "View menu: grids, Compare/Survey/Reference/People, Face Boxes, Filter Bar, Slideshow, Second Window",
        "`menus.rs` `menu_entries`",
        "Library views"
    ),
    entry!(
        "Keyboard shortcuts of every hidden command",
        "`shortcuts.rs` `fire_command`, `fire_alias`",
        "A hidden command must not be reachable by key"
    ),
    entry!(
        "Top bar icons: Discord, cloud, Import, Activity bell",
        "`panels/topbar.rs` `right_icons`",
        "ArtCraft promotion; library; Import is replaced by Open photo"
    ),
    entry!("Keywords panel, Keyword painter, Add Face Model", "`menus/ui_commands.rs`", "Library organising"),
    entry!(
        "Creative vignette controls (Effects ▸ Vignette)",
        "`panels/edit.rs` Vignette sub-section",
        "Karl: cut from the UI; lens vignetting under Optics stays"
    ),
    entry!(
        "Help ▸ Discord, ArtCraft Website, GitHub, Feedback, Website, Help, What's New",
        "`menus/ui_commands.rs`, `links.rs`",
        "Links to the ArtCraft team and the `storytold` repository"
    ),
    entry!("About dialog promotion (Discord button, more creative apps)", "`dialogs.rs` About", "ArtCraft promotion"),
    entry!(
        "Updater: startup prompt, Check for Updates, self-update",
        "`app/frame.rs`, `dialogs/updates_ui.rs`, `apps/lightcraft/src/main.rs`",
        "Would offer ArtCraft's builds; off until Cargo Bay's updater is wired in"
    ),
];

static CLEAN: AtomicBool = AtomicBool::new(false);

/// Turn the clean screen on, once, before the window is built. `PANOPTIC_SHOW_ALL` set to anything
/// but empty or `0` leaves everything shown.
pub fn enable_clean() {
    let all = std::env::var("PANOPTIC_SHOW_ALL").is_ok_and(|v| !v.is_empty() && v != "0");
    CLEAN.store(!all, Ordering::Relaxed);
}

/// Everything shown: the full app.
pub fn show_all() -> bool {
    !CLEAN.load(Ordering::Relaxed)
}

/// The app's name as the user sees it: Panoptic on the clean screen, in any label that says LightCraft.
pub fn brand(text: &str) -> String {
    if clean() { text.replace("LightCraft", "Panoptic") } else { text.to_string() }
}

/// Open Photo takes the key Open Library has in the full app (Cmd+O), unless the user bound Open Photo themselves.
pub fn open_photo_key<'a>(id: &str, keymap: &'a crate::shortcuts::Keymap) -> Option<&'a str> {
    (clean() && id == "file.openPhoto" && !keymap.contains_key("file.openPhoto")).then_some("Cmd+O")
}

/// Whether the clean screen is in force (the opposite of [`show_all`]).
pub fn clean() -> bool {
    !show_all()
}

const COMMANDS: &[&str] = &[
    "view.photoGrid",
    "view.squareGrid",
    "view.gridToggle",
    "view.compare",
    "view.survey",
    "view.people",
    "view.person",
    "view.faceBoxes",
    "view.reference",
    "photo.setReference",
    "compare.swap",
    "compare.set",
    "compare.makeSelect",
    "view.filterBar",
    "view.focusSearch",
    "view.leftPanel",
    "view.photoCounts",
    "view.sidebarSection",
    "view.sidebarMoveSection",
    "view.sidebarReset",
    "view.slideshow",
    "view.slideshowOptions",
    "dialog.slideshowExport",
    "app.slideshowExport",
    "view.secondWindow",
    "view.thumbSizeUp",
    "view.thumbSizeDown",
    "view.gridInfo",
    "local.addRoot",
    "local.hide",
    "local.restoreHidden",
    "dialog.newAlbum",
    "dialog.newFolder",
    "dialog.smartAlbum",
    "dialog.newSmartAlbum",
    "file.addPhotos",
    "file.addFolder",
    "file.importLightroom",
    "file.addFromDevice",
    "file.findMissing",
    "file.backupLibrary",
    "file.restoreLibrary",
    "file.importKeywords",
    "file.exportKeywords",
    "app.newLibrary",
    "app.openLibrary",
    "app.recentLibraries",
    "app.clearRecentLibraries",
    "dialog.cull",
    "dialog.rename",
    "dialog.print",
    "app.print",
    "dialog.contactSheet",
    "app.contactSheet",
    "app.discord",
    "app.feedback",
    "app.website",
    "app.github",
    "app.artcraft",
    "app.help",
    "app.whatsNew",
    "app.checkForUpdates",
    "photo.tagFromTracklog",
    "panel.keywords",
    "panel.addKeywords",
    "tool.keywordPainter",
    "dialog.faceModel",
];

/// The File menu keeps only these.
const FILE_MENU: &[&str] = &[
    "file.openPhoto",
    "file.openFolder",
    "dialog.export",
    "app.exportPrevious",
    "file.importPresets",
    "file.exportPresets",
    "app.settings",
    "app.quit",
];

/// A command hidden from keys, menus and buttons.
pub fn command(id: &str) -> bool {
    clean() && COMMANDS.contains(&id)
}

/// A menu entry hidden from the menu bar: a hidden command, anything in File outside its short
/// list, and the Stack sub-menu of Photo.
pub fn menu_entry(id: &str, menu: &[String]) -> bool {
    if show_all() {
        return false;
    }
    let top = menu.first().map(String::as_str);
    command(id) || (top == Some("File") && !FILE_MENU.contains(&id)) || (top == Some("Photo") && menu.get(1).map(String::as_str) == Some("Stack"))
}

/// Whether the centre view may be something other than the one photo.
pub fn library_views() -> bool {
    show_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_see_the_full_app() {
        assert!(show_all());
        assert!(!command("view.photoGrid"));
        assert!(!menu_entry("file.addFolder", &["File".to_string()]));
    }

    #[test]
    fn table_lists_the_vignette_and_the_updater() {
        assert!(TABLE.iter().any(|e| e.name.contains("vignette")));
        assert!(TABLE.iter().any(|e| e.name.starts_with("Updater")));
    }
}
