//! Manual-only, signed updates.
//!
//! * Sitrep never checks for updates by itself: only when the user clicks
//!   "Check for updates" in Settings.
//! * The only update source is this repository's GitHub Releases, over HTTPS
//!   (fixed in tauri.conf.json; the webview cannot change it).
//! * Every update must carry a valid signature from the project's private
//!   signing key. The matching public key is compiled into the app, so a
//!   tampered or unsigned download is refused even if it came from GitHub.
//! * Only strictly newer versions are installed (no downgrade attacks).
//! * The UI has no updater permission: it can only call the two commands
//!   below, which take no URLs or paths.

use semver::Version;
use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

use crate::text::to_plain;

#[derive(Serialize, Debug, PartialEq)]
pub struct UpdateInfo {
    pub current: String,
    pub available: Option<String>,
    pub notes: Option<String>,
}

/// Never install the same or an older version, whatever the manifest says.
pub fn is_newer(current: &Version, candidate: &Version) -> bool {
    candidate > current
}

fn updater(app: &AppHandle) -> Result<tauri_plugin_updater::Updater, String> {
    app.updater_builder()
        .version_comparator(|current, release| is_newer(&current, &release.version))
        .build()
        .map_err(|_| "Updater is not configured.".to_string())
}

#[tauri::command]
pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
pub async fn check_update(app: AppHandle) -> Result<UpdateInfo, String> {
    let update = updater(&app)?.check().await.map_err(|e| {
        format!(
            "Couldn't check for updates: {}",
            to_plain(&e.to_string(), 200)
        )
    })?;
    Ok(UpdateInfo {
        current: app_version(),
        available: update.as_ref().map(|u| to_plain(&u.version, 40)),
        notes: update.and_then(|u| u.body).map(|b| to_plain(&b, 1500)),
    })
}

/// Download, verify the signature, install and restart. Installation is
/// refused by the plugin if the signature doesn't match the built-in key.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<(), String> {
    let Some(update) = updater(&app)?.check().await.map_err(|e| {
        format!(
            "Couldn't check for updates: {}",
            to_plain(&e.to_string(), 200)
        )
    })?
    else {
        return Err("You're already on the latest version.".into());
    };
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| {
            format!(
                "Update failed and was not installed: {}",
                to_plain(&e.to_string(), 200)
            )
        })?;
    app.restart();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_strictly_newer_versions() {
        let cur = Version::parse("0.1.1").unwrap();
        assert!(is_newer(&cur, &Version::parse("0.1.2").unwrap()));
        assert!(is_newer(&cur, &Version::parse("1.0.0").unwrap()));
        assert!(!is_newer(&cur, &Version::parse("0.1.1").unwrap()));
        assert!(
            !is_newer(&cur, &Version::parse("0.1.0").unwrap()),
            "downgrade must be refused"
        );
        assert!(
            !is_newer(&cur, &Version::parse("0.1.1-rc.1").unwrap()),
            "pre-release of same version is older"
        );
    }
}

/// Guardrails on the shipped configuration: if anyone weakens these settings,
/// the test suite fails.
#[cfg(test)]
mod config_guardrails {
    use serde_json::Value;

    fn conf() -> Value {
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap()
    }

    #[test]
    fn updater_is_https_github_only_and_signed() {
        let c = conf();
        let up = &c["plugins"]["updater"];
        let endpoints = up["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert!(endpoints[0]
            .as_str()
            .unwrap()
            .starts_with("https://github.com/SamuelWoniowei/Sitrep/releases/"));
        assert!(
            up["pubkey"].as_str().unwrap().len() > 50,
            "update public key missing"
        );
        assert!(
            !up["pubkey"].as_str().unwrap().contains("REPLACE"),
            "set the real updater public key in tauri.conf.json before releasing"
        );
        for k in [
            "dangerousInsecureTransportProtocol",
            "dangerousAcceptInvalidCerts",
            "dangerousAcceptInvalidHostnames",
        ] {
            assert!(up.get(k).is_none() || up[k] == false, "{k} must stay off");
        }
    }

    #[test]
    fn csp_and_capabilities_stay_locked() {
        let c = conf();
        let csp = &c["app"]["security"]["csp"];
        assert_eq!(csp["default-src"], "'self'");
        assert_eq!(csp["script-src"], "'self'");
        assert_eq!(csp["object-src"], "'none'");
        assert_eq!(c["app"]["withGlobalTauri"], false);
        let caps: Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        for p in caps["permissions"].as_array().unwrap() {
            let p = p.as_str().unwrap();
            assert!(p.starts_with("core:"), "unexpected UI permission: {p}");
        }
    }
}
