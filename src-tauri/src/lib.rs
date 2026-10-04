//! Tauri shell: exposes the crypto core to the UI and handles OS integration
//! (command-line / "Open with" files, single instance, macOS open events).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use shadowcrypt_core::files::{self, FileInfo, Outcome};
use shadowcrypt_core::{Ctx, Error, Phase};
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

#[derive(Default)]
struct AppState {
    /// A file handed to us by the OS that the UI hasn't picked up yet.
    pending: Mutex<Option<PathBuf>>,
    /// Cancel flag of the running job (only one job at a time).
    job: Mutex<Option<Arc<AtomicBool>>>,
    /// Files this session produced; only these may be revealed in the file manager.
    outputs: Mutex<HashSet<PathBuf>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileDto {
    path: String,
    name: String,
    size: u64,
    encrypted: bool,
    format: Option<String>,
}

impl From<FileInfo> for FileDto {
    fn from(f: FileInfo) -> Self {
        Self {
            path: f.path.to_string_lossy().into_owned(),
            name: f.name,
            size: f.size,
            encrypted: f.format.is_some(),
            format: f.format.map(|f| f.label()),
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ProgressDto {
    phase: &'static str,
    percent: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutcomeDto {
    output_path: String,
    output_name: String,
    format: String,
}

#[derive(Serialize, Debug)]
struct ErrorDto {
    code: &'static str,
    message: String,
}

impl From<Error> for ErrorDto {
    fn from(e: Error) -> Self {
        Self { code: e.code(), message: e.to_string() }
    }
}

impl ErrorDto {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

type CmdResult<T> = Result<T, ErrorDto>;

#[tauri::command]
fn inspect_file(path: String) -> CmdResult<FileDto> {
    Ok(files::inspect(Path::new(&path))?.into())
}

/// Returns (and clears) a file passed on the command line / via "Open with".
#[tauri::command]
fn take_pending_file(state: State<'_, AppState>) -> Option<FileDto> {
    let path = state.pending.lock().unwrap().take()?;
    files::inspect(&path).ok().map(Into::into)
}

#[tauri::command]
async fn encrypt_file(
    app: AppHandle,
    path: String,
    password: String,
    output_dir: Option<String>,
    on_progress: Channel<ProgressDto>,
) -> CmdResult<OutcomeDto> {
    run_job(app, path, password, output_dir, on_progress, files::encrypt_file).await
}

#[tauri::command]
async fn decrypt_file(
    app: AppHandle,
    path: String,
    password: String,
    output_dir: Option<String>,
    on_progress: Channel<ProgressDto>,
) -> CmdResult<OutcomeDto> {
    run_job(app, path, password, output_dir, on_progress, files::decrypt_file).await
}

type JobFn = fn(&Path, Option<&Path>, &str, &mut Ctx) -> shadowcrypt_core::Result<Outcome>;

async fn run_job(
    app: AppHandle,
    path: String,
    password: String,
    output_dir: Option<String>,
    on_progress: Channel<ProgressDto>,
    job: JobFn,
) -> CmdResult<OutcomeDto> {
    let password = Zeroizing::new(password);
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let state = app.state::<AppState>();
        let mut current = state.job.lock().unwrap();
        if current.is_some() {
            return Err(ErrorDto::new("busy", "Another operation is already running"));
        }
        *current = Some(cancel.clone());
    }

    let flag = cancel.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let mut last = (u8::MAX, "");
        let mut ctx = Ctx::new(
            move |p| {
                let (phase, percent) = to_percent(p.phase, p.done, p.total);
                // Throttle: only send when something visible changes.
                if (percent, phase) != last {
                    last = (percent, phase);
                    let _ = on_progress.send(ProgressDto { phase, percent });
                }
            },
            &flag,
        );
        let out_dir = output_dir.as_deref().map(Path::new);
        job(Path::new(&path), out_dir, &password, &mut ctx)
    })
    .await
    .map_err(|e| ErrorDto::new("internal", e.to_string()));

    let state = app.state::<AppState>();
    *state.job.lock().unwrap() = None;
    let outcome = result??;
    state.outputs.lock().unwrap().insert(outcome.output.clone());
    Ok(OutcomeDto {
        output_name: outcome
            .output
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        output_path: outcome.output.to_string_lossy().into_owned(),
        format: outcome.format.label(),
    })
}

fn to_percent(phase: Phase, done: u64, total: u64) -> (&'static str, u8) {
    let frac = if total > 0 { (done as f64 / total as f64).clamp(0.0, 1.0) } else { 0.0 };
    match phase {
        Phase::DerivingKey => ("deriving_key", 2),
        Phase::Encrypting => ("encrypting", 5 + (frac * 93.0) as u8),
        Phase::Decrypting => ("decrypting", 5 + (frac * 93.0) as u8),
        Phase::Finalizing => ("finalizing", 99),
    }
}

#[tauri::command]
fn cancel(state: State<'_, AppState>) {
    if let Some(flag) = state.job.lock().unwrap().as_ref() {
        flag.store(true, Ordering::Relaxed);
    }
}

#[tauri::command]
fn reveal(path: String, state: State<'_, AppState>) -> CmdResult<()> {
    let path = PathBuf::from(path);
    if !state.outputs.lock().unwrap().contains(&path) {
        return Err(ErrorDto::new("forbidden", "Not a file produced by ShadowCrypt"));
    }
    tauri_plugin_opener::reveal_item_in_dir(&path).map_err(|e| ErrorDto::new("io", e.to_string()))
}

/// Pick the first argument that names an existing file (relative to `cwd`).
fn file_from_args(args: &[String], cwd: &Path) -> Option<PathBuf> {
    args.iter().skip(1).filter(|a| !a.starts_with('-')).find_map(|a| {
        let p = Path::new(a);
        let p = if p.is_absolute() { p.to_path_buf() } else { cwd.join(p) };
        p.is_file().then_some(p)
    })
}

/// Queue a file from the OS and tell the UI to pick it up.
fn open_file(app: &AppHandle, path: PathBuf) {
    *app.state::<AppState>().pending.lock().unwrap() = Some(path);
    let _ = app.emit("file-opened", ());
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState::default();
    let args: Vec<String> = std::env::args().collect();
    let cwd = std::env::current_dir().unwrap_or_default();
    *state.pending.lock().unwrap() = file_from_args(&args, &cwd);

    let app = tauri::Builder::default()
        // Must be registered first: a second launch (e.g. "Open with" while the
        // app is open) forwards its file here and exits.
        .plugin(tauri_plugin_single_instance::init(|app, argv, cwd| {
            match file_from_args(&argv, Path::new(&cwd)) {
                Some(path) => open_file(app, path),
                None => {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                }
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        // Closing mid-operation: cancel the job and let it clean up its temp
        // file before the process exits, instead of leaving a partial file.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let job = window.state::<AppState>().job.lock().unwrap().clone();
                if let Some(flag) = job {
                    flag.store(true, Ordering::Relaxed);
                    api.prevent_close();
                    let app = window.app_handle().clone();
                    std::thread::spawn(move || {
                        while app.state::<AppState>().job.lock().unwrap().is_some() {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                        app.exit(0);
                    });
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            inspect_file,
            take_pending_file,
            encrypt_file,
            decrypt_file,
            cancel,
            reveal
        ])
        .build(tauri::generate_context!())
        .expect("error while building ShadowCrypt");

    app.run(|_app, _event| {
        // macOS delivers "Open with" / double-clicked files as an event, not argv.
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let tauri::RunEvent::Opened { urls } = _event {
            if let Some(path) = urls.into_iter().find_map(|u| u.to_file_path().ok()) {
                open_file(_app, path);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_from_args_skips_flags_and_missing_files() {
        let dir = std::env::temp_dir();
        let file = dir.join(format!("shadowcrypt-arg-test-{}.txt", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        let name = file.file_name().unwrap().to_string_lossy().into_owned();

        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // relative path resolved against cwd; flags and missing files ignored
        assert_eq!(
            file_from_args(&args(&["app.exe", "--flag", "missing.bin", &name]), &dir),
            Some(dir.join(&name))
        );
        // absolute path
        let abs = file.to_string_lossy().into_owned();
        assert_eq!(file_from_args(&args(&["app.exe", &abs]), Path::new("/")), Some(file.clone()));
        // the executable itself is never picked, directories are not files
        assert_eq!(file_from_args(&args(&[&abs]), &dir), None);
        let d = dir.to_string_lossy().into_owned();
        assert_eq!(file_from_args(&args(&["app.exe", &d]), &dir), None);
        std::fs::remove_file(file).unwrap();
    }

    #[test]
    fn percent_mapping_is_monotonic_and_bounded() {
        assert_eq!(to_percent(Phase::DerivingKey, 0, 0), ("deriving_key", 2));
        assert_eq!(to_percent(Phase::Encrypting, 0, 100), ("encrypting", 5));
        assert_eq!(to_percent(Phase::Decrypting, 100, 100), ("decrypting", 98));
        assert_eq!(to_percent(Phase::Decrypting, 500, 100), ("decrypting", 98));
        assert_eq!(to_percent(Phase::Encrypting, 10, 0), ("encrypting", 5));
        assert_eq!(to_percent(Phase::Finalizing, 0, 0), ("finalizing", 99));
        let mut last = 0;
        for done in (0..=1000).step_by(7) {
            let (_, p) = to_percent(Phase::Encrypting, done, 1000);
            assert!(p >= last);
            last = p;
        }
    }

    #[test]
    fn error_codes_reach_the_ui() {
        let e: ErrorDto = Error::WrongPassword.into();
        assert_eq!(e.code, "wrong_password");
        let e: ErrorDto = Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)).into();
        assert_eq!(e.code, "permission_denied");
    }
}
