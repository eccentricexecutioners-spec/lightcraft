//! `cargo xtask bundle`: build the release app and wrap it as `dist/Panoptic.app` (macOS), with the
//! committed placeholder icon `assets/app-icon/panoptic.icns`. The bundle is signed ad-hoc; the
//! release road (`scripts/release-mac.sh`) builds the same layout from the `release-slim` profile.

use std::path::Path;
use std::process::Command;

pub fn run(root: &Path) -> Result<(), String> {
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(root)
        .args(["build", "--release", "-p", "lightcraft"])
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("release build failed".into());
    }
    let target = std::env::var("CARGO_TARGET_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| root.join("target"));
    let app = root.join("dist/Panoptic.app/Contents");
    let _ = std::fs::remove_dir_all(root.join("dist/Panoptic.app"));
    std::fs::create_dir_all(app.join("MacOS")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(app.join("Resources")).map_err(|e| e.to_string())?;
    std::fs::copy(target.join("release/lightcraft"), app.join("MacOS/Panoptic")).map_err(|e| format!("copy app: {e}"))?;
    std::fs::copy(root.join("assets/app-icon/panoptic.icns"), app.join("Resources/Panoptic.icns")).map_err(|e| format!("copy icon: {e}"))?;
    let sha = std::env::var("LIGHTCRAFT_BUILD_SHA").unwrap_or_else(|_| "unknown".into());
    std::fs::write(app.join("Info.plist"), info_plist(env!("CARGO_PKG_VERSION"), &sha)).map_err(|e| e.to_string())?;
    let sign = Command::new("codesign").args(["--force", "--deep", "-s", "-"]).arg(root.join("dist/Panoptic.app")).status().map_err(|e| e.to_string())?;
    if !sign.success() {
        return Err("ad-hoc codesign failed".into());
    }
    println!("built {}", root.join("dist/Panoptic.app").display());
    Ok(())
}

/// Panoptic's `Info.plist` template; `scripts/release-mac.sh` fills the same one.
const INFO_PLIST: &str = include_str!("../../packaging/macos/Panoptic.Info.plist.in");

/// The bundle's `Info.plist`: [`INFO_PLIST`] for `version` and the build commit `sha`.
fn info_plist(version: &str, sha: &str) -> String {
    let short = version.split('-').next().unwrap_or(version);
    INFO_PLIST.replace("@VERSION@", version).replace("@SHORT_VERSION@", short).replace("@BUILD_SHA@", sha)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_is_panoptic_with_every_placeholder_filled() {
        let p = info_plist("1.2.3-rc.1", "abc123");
        assert!(p.contains("<string>1.2.3</string>") && p.contains("<string>1.2.3-rc.1</string>") && p.contains("<string>abc123</string>"), "{p}");
        assert!(!p.contains('@'), "every placeholder filled");
        assert!(p.contains("<string>ca.eccentricexecutioners.panoptic</string>") && p.contains("<string>Panoptic</string>"));
        assert!(!p.contains("ArtCraft") || p.contains("Based on LightCraft by the ArtCraft team"), "only the plain-text credit may name ArtCraft");
    }
}
