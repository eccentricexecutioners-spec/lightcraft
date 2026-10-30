#!/usr/bin/env bash
# Release Panoptic for macOS through Cargo Bay, from the Mac Mini. See docs/releasing.md § Panoptic on Cargo Bay.
#
#   scripts/release-mac.sh <version> [--dry-run] [--notes "What's new"]
#
# 1. Refuses unless the fork has no tracked changes, Cargo.toml's version is <version>, and tag panoptic-v<version> is
#    new. (The fork keeps upstream LightCraft's v0.x.y tags, so Panoptic's own tags carry a prefix.)
# 2. Builds the app only (profile release-slim: stripped, thin LTO), assembles Panoptic.app as `cargo xtask bundle`
#    lays it out (without lightcraft-cli), and signs the whole bundle ad-hoc.
# 3. Commits the bundle to a one-off git repo in the release folder and tags it v<version>: Cargo Bay's release tool
#    zips with `git archive` from a tag, so the zip holds exactly one top-level Panoptic.app/ and nothing else.
# 4. Has Cargo Bay's release tool build and sign (the Mini's release key) that zip (its --dry-run), then gates it:
#    one top-level Panoptic.app; executable after unzip; codesign --verify --deep --strict; D3's uplink zip rules
#    (run by crates/uplink itself); under 50 MB (52,428,800 bytes, Supabase's upload limit). Any failure sends nothing.
# 5. Unless --dry-run: runs the release tool for real (POST /releases, upload, finalize), then tags panoptic-v<version>.
#
# Environment:
#   CARGO_BAY_DIR             the cargo-bay checkout (default ~/Eccentric-Executioners-code/cargo-bay); the tool runs there
#   CARGO_BAY_RELEASE_KEY     the release key (default: the one release-signing-rk-*.key in ~/.cargo-bay/release-keys/)
#   CARGO_BAY_PUBLISH_KEY     the publish key (default: read from ~/.cargo-bay/release-keys/publish-key)
#   PANOPTIC_RELEASE_DIR     where each release's folder goes (default ~/panoptic-releases); never overwritten
set -euo pipefail

LIMIT=52428800
TOOL=panoptic
MOTHERSHIP_PAGE="https://eccentricexecutioners.ca/dashboard/cargo-bay/${TOOL}"

die() { printf 'release-mac: %s\n' "$*" >&2; exit 1; }

VERSION="" DRY=0 NOTES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --notes) [ $# -ge 2 ] || die "--notes needs a value"; NOTES="$2"; shift ;;
    -*) die "unknown argument: $1" ;;
    *) [ -z "$VERSION" ] || die "one version only"; VERSION="$1" ;;
  esac
  shift
done
[ -n "$VERSION" ] || die "usage: scripts/release-mac.sh <version> [--dry-run] [--notes \"What's new\"]"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-beta\.(0|[1-9][0-9]*))?$ ]] \
  || die "version must look like 1.2.3 or 1.2.3-beta.4 (Cargo Bay's rule); got $VERSION"
NOTES="${NOTES:-Panoptic $VERSION}"
TAG="v$VERSION"                 # the release tool reads version and channel from this tag (staging repo)
FORK_TAG="panoptic-v$VERSION"  # this fork's tag

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CARGO_BAY_DIR="${CARGO_BAY_DIR:-$HOME/Eccentric-Executioners-code/cargo-bay}"
RELEASE_TOOL="$CARGO_BAY_DIR/tools/release.mjs"
OUT_BASE="${PANOPTIC_RELEASE_DIR:-$HOME/panoptic-releases}"
OUT="$OUT_BASE/$VERSION"

# --- 1. Refusals ---------------------------------------------------------------------------------------------------
[ "$(uname -s)" = Darwin ] || die "macOS only"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "REFUSED: the fork has tracked changes; commit or stash them"
have="$(cargo xtask version 2>/dev/null | tail -1)"
[ "$have" = "$VERSION" ] || die "REFUSED: Cargo.toml says $have, not $VERSION (cargo xtask version set $VERSION, then commit)"
git rev-parse -q --verify "refs/tags/$FORK_TAG" >/dev/null && die "REFUSED: tag $FORK_TAG already exists here (versions are never reused)"
[ -f "$RELEASE_TOOL" ] || die "no Cargo Bay release tool at $RELEASE_TOOL (set CARGO_BAY_DIR)"
command -v node >/dev/null || die "node is not installed"
if [ -z "${CARGO_BAY_RELEASE_KEY:-}" ]; then
  keys=("$HOME"/.cargo-bay/release-keys/release-signing-rk-*.key)
  [ -f "${keys[0]}" ] || die "no release key in ~/.cargo-bay/release-keys/ (set CARGO_BAY_RELEASE_KEY)"
  [ "${#keys[@]}" -eq 1 ] || die "more than one release key in ~/.cargo-bay/release-keys/; set CARGO_BAY_RELEASE_KEY"
  CARGO_BAY_RELEASE_KEY="${keys[0]}"
fi
KEY_ID="$(basename "$CARGO_BAY_RELEASE_KEY" .key)"; KEY_ID="${KEY_ID#release-signing-}"
if [ "$DRY" = 0 ] && [ -z "${CARGO_BAY_PUBLISH_KEY:-}" ]; then
  pk="$HOME/.cargo-bay/release-keys/publish-key"
  [ -f "$pk" ] || die "CARGO_BAY_PUBLISH_KEY is not set and $pk does not exist"
  CARGO_BAY_PUBLISH_KEY="$(tr -d '[:space:]' < "$pk")"
fi
[ ! -e "$OUT" ] || die "REFUSED: $OUT already exists; nothing is overwritten"

# --- 2. Slim build, bundle, ad-hoc signature --------------------------------------------------------------------------
SHA="$(git rev-parse --short HEAD)"
echo "release-mac: building Panoptic $VERSION ($SHA), profile release-slim"
LIGHTCRAFT_BUILD_SHA="$SHA" cargo build --profile release-slim -p lightcraft
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="$TARGET/release-slim/lightcraft"

STAGE="$OUT/stage"
APP="$STAGE/Panoptic.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Panoptic"
cp assets/app-icon/panoptic.icns "$APP/Contents/Resources/Panoptic.icns"
SHORT="${VERSION%%-*}"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@SHORT_VERSION@/$SHORT/g" -e "s/@BUILD_SHA@/$SHA/g" \
  packaging/macos/Panoptic.Info.plist.in > "$APP/Contents/Info.plist"
grep -q '@' "$APP/Contents/Info.plist" && grep -n '@[A-Z_]*@' "$APP/Contents/Info.plist" && die "Info.plist placeholder left"
codesign --force --deep -s - "$APP"
codesign --verify --deep --strict "$APP"

# --- 3. The bundle as a git tag (Cargo Bay's release tool zips with git archive) --------------------------------------
git -C "$STAGE" init -q
git -C "$STAGE" add Panoptic.app
git -C "$STAGE" -c user.name="Panoptic release" -c user.email="release@localhost" commit -q -m "Panoptic $VERSION ($SHA)"
git -C "$STAGE" tag "$TAG"

# --- 4. Build, sign and check the zip with the release tool's dry run -------------------------------------------------
release_tool() { (cd "$CARGO_BAY_DIR" && node tools/release.mjs --repo "$STAGE" --tag "$TAG" --path Panoptic.app \
  --tool "$TOOL" --kind desktop-app --platform mac --notes "$NOTES" --key "$CARGO_BAY_RELEASE_KEY" "$@"); }
release_tool --dry-run "$OUT/signed"
ZIP="$OUT/signed/Panoptic.app-$VERSION.zip"
BYTES="$(stat -f %z "$ZIP")"
echo "release-mac: zip $BYTES bytes; binary $(stat -f %z "$APP/Contents/MacOS/Panoptic") bytes; key $KEY_ID"

# The gate: five checks on the tool's own zip; any failure stops before anything is sent.
gate() { echo "release-mac: GATE $1: PASS — $2"; }
# 1. One top-level Panoptic.app, no __MACOSX (and no lightcraft-cli).
tops="$(zipinfo -1 "$ZIP" | cut -d/ -f1 | sort -u)"
[ "$tops" = "Panoptic.app" ] || die "GATE 1 FAIL: the zip's top level is not exactly Panoptic.app: $tops"
zipinfo -1 "$ZIP" | grep -q -E '(^|/)(__MACOSX|lightcraft-cli)(/|$)' && die "GATE 1 FAIL: the zip holds __MACOSX or lightcraft-cli"
gate 1 "one top-level Panoptic.app, no __MACOSX, no lightcraft-cli ($(zipinfo -1 "$ZIP" | wc -l | tr -d ' ') entries)"
# 4. D3's uplink rules, run by the uplink crate itself: signature (the release key as a listed key), size, sha256,
#    entry rules, then its own unzip and tree comparison (size, CRC-32, executable bit, nothing extra).
CHECKER="$OUT/zipcheck"
mkdir -p "$CHECKER/src"
cat > "$CHECKER/Cargo.toml" <<TOML
[package]
name = "panoptic-zipcheck"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
panoptic-uplink = { path = "$ROOT/crates/uplink" }
serde_json = "1"
TOML
cat > "$CHECKER/src/main.rs" <<'RUST'
use std::path::Path;
use panoptic_uplink::trust::{parse_spki_pem, Trust};
use panoptic_uplink::zipcheck;

fn read(p: &str) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    let [_, zip, manifest, sig, public, dest] = args.as_slice() else {
        return Err("usage: panoptic-zipcheck <zip> <manifest.json> <manifest.json.sig> <release .pub> <new dir>".into());
    };
    let key = parse_spki_pem(&read(public)?)?;
    let trust = Trust { master: [0u8; 32], extra_masters: Vec::new(), release: vec![key] };
    let manifest: serde_json::Value = serde_json::from_str(&read(manifest)?).map_err(|e| e.to_string())?;
    let entries = zipcheck::verify_package(&trust, Path::new(zip), &manifest, read(sig)?.trim())?;
    std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    zipcheck::extract(Path::new(zip), &entries, Path::new(dest))?;
    zipcheck::tree_matches(&entries, &Path::new(dest).join("Panoptic.app"))?;
    Ok(format!("signature, size, sha256 and entry rules pass ({} entries); unzipped tree matches the zip", entries.len()))
}

fn main() {
    match run() {
        Ok(line) => println!("{line}"),
        Err(e) => {
            eprintln!("panoptic-zipcheck: {e}");
            std::process::exit(1);
        }
    }
}
RUST
UPLINK_UNZIP="$OUT/unzipped-uplink"
line="$(CARGO_TARGET_DIR="$TARGET/zipcheck" cargo run -q --release --manifest-path "$CHECKER/Cargo.toml" -- \
  "$ZIP" "$OUT/signed/manifest.json" "$OUT/signed/manifest.json.sig" "${CARGO_BAY_RELEASE_KEY%.key}.pub" "$UPLINK_UNZIP")" \
  || die "GATE 4 FAIL: the zip fails D3's uplink rules"
gate 4 "D3 uplink: $line"
# 2. Contents/MacOS/Panoptic executable after unzip (the updater's unzip and ditto's).
DITTO_UNZIP="$OUT/unzipped-ditto"
mkdir -p "$DITTO_UNZIP"
ditto -x -k "$ZIP" "$DITTO_UNZIP"
for d in "$UPLINK_UNZIP" "$DITTO_UNZIP"; do
  [ -f "$d/Panoptic.app/Contents/MacOS/Panoptic" ] && [ -x "$d/Panoptic.app/Contents/MacOS/Panoptic" ] \
    || die "GATE 2 FAIL: Contents/MacOS/Panoptic is not executable after unzip in $d"
done
gate 2 "Contents/MacOS/Panoptic is executable after the uplink unzip and after ditto -x -k"
# 3. The ad-hoc signature survives the zip.
for d in "$UPLINK_UNZIP" "$DITTO_UNZIP"; do
  codesign --verify --deep --strict "$d/Panoptic.app" || die "GATE 3 FAIL: codesign --verify --deep --strict fails in $d"
done
gate 3 "codesign --verify --deep --strict passes on both unzipped copies"
# 5. Under Cargo Bay's 50 MB upload limit.
[ "$BYTES" -lt "$LIMIT" ] || die "GATE 5 FAIL (STOP): the zip is $BYTES bytes, at or over $LIMIT; nothing sent"
gate 5 "$BYTES bytes < $LIMIT"
# The real run zips the same tag again. git archive stamps a tree's entries with the current time, so that zip differs
# from the checked one in its time stamps only: check that, here on a second zip and after the release on the one sent.
same_but_times() {
  python3 -I - "$1" "$2" <<'PY'
import os, struct, sys, zipfile
a, b = sys.argv[1:]
def untimed(extra):
    # Zero the payload of the extended-timestamp field (0x5455, "UT"); keep every other byte.
    out, i = b"", 0
    while i + 4 <= len(extra):
        hid, n = struct.unpack("<HH", extra[i:i + 4])
        body = extra[i + 4:i + 4 + n]
        out += extra[i:i + 4] + (bytes(len(body)) if hid == 0x5455 else body)
        i += 4 + n
    return out + extra[i:]
key = lambda z: [(e.filename, e.CRC, e.compress_size, e.file_size, e.external_attr, e.compress_type, e.create_system,
                  e.flag_bits, e.header_offset, untimed(e.extra)) for e in z.infolist()]
ok = os.path.getsize(a) == os.path.getsize(b) and key(zipfile.ZipFile(a)) == key(zipfile.ZipFile(b))
sys.exit(0 if ok else 1)
PY
}
release_tool --dry-run "$OUT/signed-again" >/dev/null
same_but_times "$ZIP" "$OUT/signed-again/Panoptic.app-$VERSION.zip" \
  || die "a second zip of this tag differs from the checked one beyond time stamps; nothing sent"
echo "release-mac: a second zip of this tag matches the checked one in everything but time stamps"

if [ "$DRY" = 1 ]; then
  echo "release-mac: dry run: $ZIP ($BYTES bytes), manifest signed by $KEY_ID. Nothing sent, no tag made."
  exit 0
fi

# --- 5. Release, then tag ---------------------------------------------------------------------------------------------
CARGO_BAY_PUBLISH_KEY="$CARGO_BAY_PUBLISH_KEY" release_tool | tee "$OUT/release.txt"
# The tool leaves the zip it sent in a fresh $TMPDIR/cargo-bay-release-* folder; Cargo Bay finalized it by its sha256.
sent="$(ls -t "${TMPDIR:-/tmp}"/cargo-bay-release-*/"Panoptic.app-$VERSION.zip" 2>/dev/null | head -1 || true)"
if [ -n "$sent" ] && same_but_times "$ZIP" "$sent"; then
  echo "release-mac: the zip sent ($sent, sha256 $(shasum -a 256 < "$sent" | cut -d' ' -f1)) matches the checked one but for time stamps" | tee -a "$OUT/release.txt"
else
  echo "release-mac: WARNING: could not match the zip sent (${sent:-not found}) to the checked one; check it by hand" | tee -a "$OUT/release.txt"
fi
git tag -a "$FORK_TAG" -m "Panoptic $VERSION, released through Cargo Bay (signed by $KEY_ID)"
echo "release-mac: tagged $FORK_TAG here (not pushed). Signed by $KEY_ID."
echo "release-mac: Mothership tool page: $MOTHERSHIP_PAGE"
