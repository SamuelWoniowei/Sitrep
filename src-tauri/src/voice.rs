//! Optional natural British voice using Piper, fully on this computer.
//!
//! One-time download (about 85 MB), then everything runs offline:
//! * Piper (the speech program) from its official GitHub release, and the
//!   "Alan" British male voice from its official Hugging Face repository.
//! * Both downloads are pinned to an exact SHA-256 and a size cap. A file
//!   that does not match is deleted and never used.
//! * The voice's small config file is built into the app, not downloaded.
//! * Before every use the Piper program, its libraries and the voice model are
//!   re-hashed against the pinned values. Anything changed is refused.
//! * Text is given to Piper on standard input only (never on a command line),
//!   and the program is started directly, with no shell.

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use reqwest::{redirect, Client};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::net::read_capped;
use crate::text::strip_controls;

pub const PIPER_URL: &str =
    "https://github.com/rhasspy/piper/releases/download/2023.11.14-2/piper_windows_amd64.zip";
pub const PIPER_SHA256: &str = "f3c58906402b24f3a96d92145f58acba6d86c9b5db896d207f78dc80811efcea";
pub const PIPER_MAX_BYTES: usize = 30 * 1024 * 1024;

pub const VOICE_URL: &str =
    "https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_GB/alan/medium/en_GB-alan-medium.onnx";
pub const VOICE_SHA256: &str = "0a309668932205e762801f1efc2736cd4b0120329622adf62be09e56339d3330";
pub const VOICE_MAX_BYTES: usize = 80 * 1024 * 1024;

const VOICE_CONFIG: &str = include_str!("../resources/en_GB-alan-medium.onnx.json");

/// Files that must match exactly each time Piper is run (paths inside the
/// unpacked `piper` folder).
const PINNED_FILES: &[(&str, &str)] = &[
    (
        "piper.exe",
        "96f3da3811151580073e40bb4dd20eb0fb8115f5f5f76e2fb54282b3edfa5c1f",
    ),
    (
        "espeak-ng.dll",
        "9588480f8197df62fd8461a8431f8eaec6e8e7749c5ffcbe7fee656fe40a2189",
    ),
    (
        "onnxruntime.dll",
        "a630f67f4a82b6689e4178bf81d362d945522dd907b2a92cb43cebf72c83a06f",
    ),
    (
        "onnxruntime_providers_shared.dll",
        "71705b9bd76baced583eb37fe5ec2101946b4de50f1e9bdb156109f7e8082980",
    ),
    (
        "piper_phonemize.dll",
        "4b5f344b2f31204a8a94a0bf485f93e4971671e81188a0d67f326e113bfb0b2e",
    ),
];

const MAX_UNPACKED_BYTES: u64 = 120 * 1024 * 1024;
const MAX_UNPACKED_FILES: usize = 1000;
pub const SAMPLE_RATE: u32 = 22_050;
const MAX_TEXT_CHARS: usize = 8_000;
const MAX_PCM_BYTES: usize = 60 * 1024 * 1024;
const SYNTH_TIMEOUT: Duration = Duration::from_secs(120);

// ---------------- download ----------------

/// Hosts a download may be redirected through. The SHA-256 pin is what makes
/// the content trustworthy; this just keeps the traffic where it should be.
pub fn download_host_ok(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "github.com"
        || h.ends_with(".githubusercontent.com")
        || h == "huggingface.co"
        || h == "hf.co"
        || h.ends_with(".hf.co")
}

fn download_url_ok(u: &Url) -> bool {
    u.scheme() == "https"
        && u.username().is_empty()
        && u.password().is_none()
        && u.port().map(|p| p == 443).unwrap_or(true)
        && matches!(u.host(), Some(url::Host::Domain(d)) if download_host_ok(d))
}

pub fn download_client() -> reqwest::Result<Client> {
    Client::builder()
        .https_only(true)
        .user_agent("Sitrep/0.2")
        .timeout(Duration::from_secs(600))
        .connect_timeout(Duration::from_secs(15))
        .redirect(redirect::Policy::custom(|a| {
            if a.previous().len() >= 6 || !download_url_ok(a.url()) {
                a.stop()
            } else {
                a.follow()
            }
        }))
        .build()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn verify_hash(data: &[u8], want: &str) -> Result<(), String> {
    if sha256_hex(data).eq_ignore_ascii_case(want) {
        Ok(())
    } else {
        Err("The download did not match its expected checksum, so it was discarded.".into())
    }
}

async fn download_pinned(
    client: &Client,
    raw: &str,
    max: usize,
    want: &str,
) -> Result<Vec<u8>, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;
    if !download_url_ok(&url) {
        return Err("download host not allowed".into());
    }
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|_| "Could not reach the download server.".to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Download failed (HTTP {}).", resp.status()));
    }
    if !download_url_ok(resp.url()) {
        return Err("redirected outside allowlist".into());
    }
    let bytes = read_capped(resp, max).await?;
    verify_hash(&bytes, want)?;
    Ok(bytes)
}

// ---------------- unpack ----------------

/// Extract a zip into `dest`, refusing path tricks, symlinks, huge archives.
pub fn unpack(zip_bytes: &[u8], dest: &Path) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(zip_bytes)).map_err(|e| e.to_string())?;
    if zip.len() > MAX_UNPACKED_FILES {
        return Err("archive has too many files".into());
    }
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        // `enclosed_name` rejects absolute paths and any `..` escape.
        let rel = f.enclosed_name().ok_or("unsafe path in archive")?;
        if f.unix_mode()
            .map(|m| m & 0o170000 == 0o120000)
            .unwrap_or(false)
        {
            return Err("symbolic links are not allowed".into());
        }
        let out = dest.join(rel);
        if f.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        total = total.saturating_add(f.size());
        if total > MAX_UNPACKED_BYTES {
            return Err("archive is too large when unpacked".into());
        }
        if let Some(p) = out.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        // Copy at most the size we budgeted for (guards against a lying header).
        let mut limited = (&mut f).take(MAX_UNPACKED_BYTES);
        let mut file = std::fs::File::create(&out).map_err(|e| e.to_string())?;
        std::io::copy(&mut limited, &mut file).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---------------- paths and checks ----------------

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
    pub piper_dir: PathBuf,
    pub exe: PathBuf,
    pub model: PathBuf,
    pub config: PathBuf,
}

pub fn paths(app_data: &Path) -> Paths {
    let root = app_data.join("voice");
    let piper_dir = root.join("piper");
    Paths {
        exe: piper_dir.join("piper.exe"),
        model: root.join("en_GB-alan-medium.onnx"),
        config: root.join("en_GB-alan-medium.onnx.json"),
        piper_dir,
        root,
    }
}

fn hash_file(p: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(p).map_err(|_| "voice files missing".to_string())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Re-check every pinned file. Any difference means the voice is not used.
pub fn verify_install(p: &Paths) -> Result<(), String> {
    for (name, want) in PINNED_FILES {
        if !hash_file(&p.piper_dir.join(name))?.eq_ignore_ascii_case(want) {
            return Err(format!("{name} has changed; reinstall the voice."));
        }
    }
    if !hash_file(&p.model)?.eq_ignore_ascii_case(VOICE_SHA256) {
        return Err("The voice model has changed; reinstall the voice.".into());
    }
    if std::fs::read_to_string(&p.config).map_err(|e| e.to_string())? != VOICE_CONFIG {
        return Err("The voice config has changed; reinstall the voice.".into());
    }
    Ok(())
}

pub fn is_installed(p: &Paths) -> bool {
    p.exe.is_file() && p.model.is_file() && p.config.is_file()
}

// ---------------- speaking ----------------

/// Prepare text for Piper: plain, no control characters, one utterance per
/// line, bounded in size.
pub fn speech_text(parts: &[String]) -> String {
    let mut out = String::new();
    for part in parts {
        let clean: String = strip_controls(part)
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
        if clean.is_empty() {
            continue;
        }
        out.push_str(&clean);
        out.push('\n');
        if out.chars().count() > MAX_TEXT_CHARS {
            break;
        }
    }
    out.chars().take(MAX_TEXT_CHARS).collect()
}

/// Run a Piper-compatible program: text in on stdin, raw 16-bit mono PCM out.
pub async fn synth(exe: &Path, args: &[&str], cwd: &Path, text: &str) -> Result<Vec<u8>, String> {
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let mut child = cmd
        .spawn()
        .map_err(|_| "Could not start the voice engine.".to_string())?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let text = text.to_owned();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(text.as_bytes()).await;
        let _ = stdin.shutdown().await;
    });
    let reader = async {
        let mut pcm = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = stdout.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            if pcm.len() + n > MAX_PCM_BYTES {
                return Err("voice output too large".to_string());
            }
            pcm.extend_from_slice(&buf[..n]);
        }
        Ok(pcm)
    };
    let pcm = tokio::time::timeout(SYNTH_TIMEOUT, reader)
        .await
        .map_err(|_| "The voice engine took too long.".to_string())??;
    let _ = writer.await;
    let _ = child.wait().await;
    if pcm.len() < 2_000 {
        return Err("The voice engine produced no audio.".into());
    }
    Ok(pcm)
}

/// Pull the raw PCM out of a WAV file (16-bit mono is what Piper writes).
pub fn wav_pcm(wav: &[u8]) -> Result<&[u8], String> {
    if wav.len() < 44 || &wav[0..4] != b"RIFF" || &wav[8..12] != b"WAVE" {
        return Err("The voice engine wrote an unreadable audio file.".into());
    }
    let mut i = 12;
    while i + 8 <= wav.len() {
        let id = &wav[i..i + 4];
        let size = u32::from_le_bytes([wav[i + 4], wav[i + 5], wav[i + 6], wav[i + 7]]) as usize;
        let start = i + 8;
        if id == b"data" {
            // Streaming writers may leave the size as 0 or 0xFFFFFFFF.
            let end = if size == 0 || size > wav.len() - start { wav.len() } else { start + size };
            return Ok(&wav[start..end]);
        }
        i = start.saturating_add(size).saturating_add(size & 1);
    }
    Err("The voice engine wrote an audio file with no sound in it.".into())
}

/// Run Piper writing a WAV file (not stdout, so Windows cannot mangle the
/// bytes), then return the PCM. The file is deleted straight afterwards.
pub async fn synth_file(
    exe: &Path,
    args: &[&str],
    cwd: &Path,
    out_file: &Path,
    text: &str,
) -> Result<Vec<u8>, String> {
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(args)
        .arg("--output_file")
        .arg(out_file)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Could not start the voice engine ({}).", e.kind()))?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let mut stderr = child.stderr.take().ok_or("no stderr")?;
    let text = text.to_owned();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(text.as_bytes()).await;
        let _ = stdin.shutdown().await;
    });
    // Keep only the last few KB of the engine's log, for a useful error.
    let log = tokio::spawn(async move {
        let mut tail: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 8 * 1024];
        while let Ok(n) = stderr.read(&mut buf).await {
            if n == 0 {
                break;
            }
            tail.extend_from_slice(&buf[..n]);
            if tail.len() > 4096 {
                let cut = tail.len() - 4096;
                tail.drain(..cut);
            }
        }
        String::from_utf8_lossy(&tail).to_string()
    });
    let status = tokio::time::timeout(SYNTH_TIMEOUT, child.wait()).await;
    let _ = writer.await;
    let log = log.await.unwrap_or_default();
    let status = match status {
        Err(_) => {
            let _ = child.kill().await;
            let _ = std::fs::remove_file(out_file);
            return Err("The voice engine took too long.".into());
        }
        Ok(r) => r.map_err(|e| e.to_string())?,
    };
    let bytes = std::fs::read(out_file);
    let _ = std::fs::remove_file(out_file);
    if !status.success() {
        let last = log.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
        let last: String = last.chars().take(160).collect();
        return Err(format!("The voice engine stopped ({status}). {last}"));
    }
    let bytes = bytes.map_err(|_| "The voice engine produced no audio file.".to_string())?;
    if bytes.len() > MAX_PCM_BYTES + 1024 {
        return Err("voice output too large".into());
    }
    let pcm = wav_pcm(&bytes)?.to_vec();
    if pcm.len() < 2_000 {
        return Err("The voice engine produced no audio.".into());
    }
    Ok(pcm)
}

// ---------------- commands ----------------

#[derive(Serialize)]
pub struct VoiceStatus {
    pub installed: bool,
    pub voice: &'static str,
    pub size_mb: u32,
    pub sample_rate: u32,
}

fn app_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_data_dir().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn voice_status(app: AppHandle) -> Result<VoiceStatus, String> {
    let p = paths(&app_dir(&app)?);
    Ok(VoiceStatus {
        installed: is_installed(&p),
        voice: "Alan (British, male)",
        size_mb: 85,
        sample_rate: SAMPLE_RATE,
    })
}

#[tauri::command]
pub async fn voice_install(app: AppHandle) -> Result<VoiceStatus, String> {
    let dir = app_dir(&app)?;
    let client = download_client().map_err(|e| e.to_string())?;
    let zip = download_pinned(&client, PIPER_URL, PIPER_MAX_BYTES, PIPER_SHA256).await?;
    let model = download_pinned(&client, VOICE_URL, VOICE_MAX_BYTES, VOICE_SHA256).await?;

    // Build in a temporary folder, verify, then swap into place.
    let tmp = dir.join("voice.tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let built = (|| -> Result<(), String> {
        unpack(&zip, &tmp)?;
        std::fs::write(tmp.join("en_GB-alan-medium.onnx"), &model).map_err(|e| e.to_string())?;
        std::fs::write(tmp.join("en_GB-alan-medium.onnx.json"), VOICE_CONFIG)
            .map_err(|e| e.to_string())?;
        verify_install(&paths_in(&tmp))
    })();
    if let Err(e) = built {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    let p = paths(&dir);
    let _ = std::fs::remove_dir_all(&p.root);
    std::fs::rename(&tmp, &p.root).map_err(|e| e.to_string())?;
    voice_status(app)
}

fn paths_in(root: &Path) -> Paths {
    let piper_dir = root.join("piper");
    Paths {
        root: root.to_path_buf(),
        exe: piper_dir.join("piper.exe"),
        model: root.join("en_GB-alan-medium.onnx"),
        config: root.join("en_GB-alan-medium.onnx.json"),
        piper_dir,
    }
}

#[tauri::command]
pub fn voice_remove(app: AppHandle) -> Result<VoiceStatus, String> {
    let p = paths(&app_dir(&app)?);
    let _ = std::fs::remove_dir_all(&p.root);
    voice_status(app)
}

/// Speak the given lines. Returns raw 16-bit mono PCM at 22,050 Hz.
#[tauri::command]
pub async fn speak_piper(
    app: AppHandle,
    parts: Vec<String>,
) -> Result<tauri::ipc::Response, String> {
    if parts.len() > 40 {
        return Err("too much text".into());
    }
    let text = speech_text(&parts);
    if text.is_empty() {
        return Err("nothing to say".into());
    }
    let p = paths(&app_dir(&app)?);
    if !is_installed(&p) {
        return Err("The natural voice is not installed.".into());
    }
    let pc = p.clone();
    tokio::task::spawn_blocking(move || verify_install(&pc))
        .await
        .map_err(|e| e.to_string())??;
    let model = p.model.to_string_lossy().to_string();
    let config = p.config.to_string_lossy().to_string();
    let out_file = p.root.join(format!(
        "speech-{}-{}.wav",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let pcm = synth_file(
        &p.exe,
        &["--model", &model, "--config", &config],
        &p.piper_dir,
        &out_file,
        &text,
    )
    .await?;
    Ok(tauri::ipc::Response::new(pcm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn download_hosts_are_strict() {
        for ok in [
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "huggingface.co",
            "cdn-lfs.hf.co",
            "cas-bridge.xethub.hf.co",
        ] {
            assert!(download_host_ok(ok), "{ok}");
        }
        for bad in [
            "evil.example",
            "github.com.evil.example",
            "githubusercontent.com.evil.example",
            "evilgithub.com",
            "nothf.co",
            "huggingface.co.evil.example",
            "127.0.0.1",
        ] {
            assert!(!download_host_ok(bad), "{bad}");
        }
        assert!(download_url_ok(&Url::parse(PIPER_URL).unwrap()));
        assert!(download_url_ok(&Url::parse(VOICE_URL).unwrap()));
        assert!(!download_url_ok(
            &Url::parse("http://github.com/x").unwrap()
        ));
        assert!(!download_url_ok(
            &Url::parse("https://github.com:8443/x").unwrap()
        ));
        assert!(!download_url_ok(
            &Url::parse("https://u:p@github.com/x").unwrap()
        ));
    }

    #[test]
    fn wrong_checksum_is_rejected() {
        assert!(verify_hash(b"hello", PIPER_SHA256).is_err());
        assert!(verify_hash(
            b"hello",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        .is_ok());
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = zip::write::SimpleFileOptions::default();
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sitrep-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn unpack_extracts_normal_files() {
        let d = tmpdir("ok");
        unpack(
            &make_zip(&[("piper/piper.exe", b"x"), ("piper/data/a.txt", b"y")]),
            &d,
        )
        .unwrap();
        assert!(d.join("piper/piper.exe").is_file() && d.join("piper/data/a.txt").is_file());
    }

    #[test]
    fn unpack_refuses_path_escape() {
        let d = tmpdir("slip");
        let evil = make_zip(&[("../../evil.txt", b"x")]);
        assert!(unpack(&evil, &d).is_err());
        let abs = make_zip(&[("/tmp/evil-abs.txt", b"x")]);
        assert!(unpack(&abs, &d).is_err());
        assert!(!d.parent().unwrap().join("evil.txt").exists());
        assert!(!Path::new("/tmp/evil-abs.txt").exists());
    }

    #[test]
    fn unpack_refuses_zip_bomb_by_size() {
        let d = tmpdir("bomb");
        let big = vec![0u8; (MAX_UNPACKED_BYTES as usize) + 1];
        assert!(unpack(&make_zip(&[("a.bin", &big)]), &d).is_err());
    }

    #[test]
    fn speech_text_is_plain_and_bounded() {
        let t = speech_text(&[
            "Hello\u{202e} world\n\n  and\tmore".into(),
            "".into(),
            "--model /etc/passwd".into(),
        ]);
        assert_eq!(t, "Hello world and more\n--model /etc/passwd\n");
        let long = speech_text(&["a ".repeat(20_000)]);
        assert!(long.chars().count() <= MAX_TEXT_CHARS);
    }

    #[test]
    fn voice_config_is_valid_and_complete() {
        let v: serde_json::Value = serde_json::from_str(VOICE_CONFIG).unwrap();
        assert_eq!(v["audio"]["sample_rate"], SAMPLE_RATE);
        let map = v["phoneme_id_map"].as_object().unwrap();
        assert_eq!(map.len(), 154);
        let mut ids: Vec<i64> = map.values().map(|a| a[0].as_i64().unwrap()).collect();
        ids.sort();
        assert_eq!(ids, (0..154).collect::<Vec<_>>());
    }

    #[test]
    fn pinned_hashes_look_sane() {
        for (_, h) in PINNED_FILES {
            assert_eq!(h.len(), 64);
        }
        assert_eq!(PIPER_SHA256.len(), 64);
        assert_eq!(VOICE_SHA256.len(), 64);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn synth_passes_text_on_stdin_only() {
        let d = tmpdir("synth");
        let script = d.join("fake.sh");
        // Echo stdin back (as "audio"), padded so it passes the min-size check.
        std::fs::write(&script, "#!/bin/sh\ncat\nhead -c 4000 /dev/zero\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = synth(
            &script,
            &["--output_raw"],
            &d,
            "hello; rm -rf / $(whoami)\n",
        )
        .await
        .unwrap();
        assert!(out.starts_with(b"hello; rm -rf / $(whoami)\n"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn synth_caps_runaway_output() {
        let d = tmpdir("runaway");
        let script = d.join("fake.sh");
        std::fs::write(&script, "#!/bin/sh\nyes | head -c 70000000\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(synth(&script, &[], &d, "x").await.is_err());
    }

    #[test]
    fn wav_header_is_stripped() {
        let mut w = b"RIFF\0\0\0\0WAVEfmt ".to_vec();
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&[0u8; 16]);
        w.extend_from_slice(b"data");
        w.extend_from_slice(&4u32.to_le_bytes());
        w.extend_from_slice(&[1, 2, 3, 4, 9, 9]);
        assert_eq!(wav_pcm(&w).unwrap(), &[1, 2, 3, 4]);
        assert!(wav_pcm(b"nope").is_err());
        // Streaming size 0 means "to the end".
        let n = w.len() - 6 - 4;
        w[n..n + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(wav_pcm(&w).unwrap().len(), 6);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn synth_file_reads_wav_and_cleans_up() {
        let d = tmpdir("synthfile");
        let script = d.join("fake.sh");
        // Last arg is the output path; write a tiny WAV with 4000 bytes of data.
        std::fs::write(
            &script,
            "#!/bin/sh\ncat >/dev/null\nfor a; do o=$a; done\n{ printf 'RIFF\\0\\0\\0\\0WAVEfmt '; printf '\\20\\0\\0\\0'; head -c 16 /dev/zero; printf 'data'; printf '\\240\\17\\0\\0'; head -c 4000 /dev/zero; } > \"$o\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = d.join("o.wav");
        let pcm = synth_file(&script, &[], &d, &out, "hi").await.unwrap();
        assert_eq!(pcm.len(), 4000);
        assert!(!out.exists());
    }

    #[test]
    fn tampered_install_is_refused() {
        let d = tmpdir("tamper");
        let p = paths_in(&d);
        std::fs::create_dir_all(&p.piper_dir).unwrap();
        std::fs::write(&p.exe, b"not the real piper").unwrap();
        assert!(verify_install(&p).is_err());
    }
}
