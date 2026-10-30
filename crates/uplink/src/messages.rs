//! The English lines the app shows. `{new}` / `{old}` / `{version}` are filled by [`fill`].

pub const STAGING: &str = "Getting {new} ready…";
pub const STAGED: &str = "{new} ready — Restart to update";
pub const UPDATED_FROM: &str = "Updated to {new} (was {old})";
pub const UP_TO_DATE: &str = "Panoptic {version} is up to date";
pub const ELSEWHERE: &str = "{new} is available — download it from the Mothership's Tools page";
pub const LINKED: &str = "Linked. Panoptic will update itself.";
pub const BAD_CODE: &str = "That code didn't work. Codes last 15 minutes — get a new one on your Tools page.";
pub const NO_ACCESS: &str = "Your access to Panoptic was turned off.";
pub const RATE_LIMITED: &str = "Too many tries — wait a few minutes, then try again.";
pub const OFFLINE: &str = "Can't reach Cargo Bay — check your internet and try again.";
pub const TLS_FAILED: &str = "Can't check for updates securely from this computer.";
pub const SERVER_ERROR: &str = "Cargo Bay had a problem — try again later.";
pub const LINK_REMOVED: &str = "This copy is no longer linked — link it again from Help.";
pub const NOT_LINKED: &str = "Link Panoptic to Cargo Bay to get updates.";
pub const VERIFY_FAILED: &str = "This update didn't pass its safety check, so it wasn't installed.";
pub const INSTALL_FAILED: &str = "The new version couldn't be put in place, so your old one is back.";
pub const STAGE_FAILED: &str = "Couldn't get the update ready — try again later.";
pub const OFF: &str = "Updates are off in this copy.";

/// Replace each `{key}` in `template` with its value.
pub fn fill(template: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (key, value) in pairs {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}
