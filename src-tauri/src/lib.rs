pub mod ai;
pub mod commands;
pub mod core;
pub mod countries;
pub mod feeds;
pub mod glossary;
pub mod intel;
pub mod liveops;
pub mod net;
pub mod store;
pub mod text;
pub mod themes;
pub mod updates;
pub mod voice;

use std::sync::Mutex;

use tauri::Manager;

use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // The database lives in the per-user app data folder, readable only
            // by the current OS user.
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let store = store::Store::open(&dir.join("data.sqlite3"))?;
            app.manage(AppState {
                store: Mutex::new(store),
                feed_client: net::feed_client()?,
                ai_client: net::ai_client()?,
                article_client: net::article_client()?,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::refresh,
            commands::get_today,
            commands::mark_read,
            commands::open_story,
            commands::ai_status,
            commands::set_ai,
            commands::set_full_articles,
            commands::enhance_story,
            commands::get_focus,
            commands::set_focus,
            commands::focus_options,
            commands::ask_story,
            commands::list_ideas,
            commands::star_idea,
            commands::dismiss_idea,
            commands::restore_idea,
            commands::delete_idea,
            commands::get_project,
            commands::toggle_project_step,
            commands::complete_project,
            commands::list_built,
            commands::get_glossary,
            commands::set_term_status,
            commands::get_actors,
            commands::get_liveops,
            commands::get_animations,
            commands::set_animations,
            commands::check_exposure,
            commands::export_lab_pack,
            commands::answer_quiz,
            commands::get_recap,
            commands::get_radar,
            commands::get_watchlist,
            commands::add_watch,
            commands::remove_watch,
            commands::list_sources,
            updates::app_version,
            updates::check_update,
            updates::install_update,
            voice::voice_status,
            voice::voice_install,
            voice::voice_remove,
            voice::speak_piper,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
