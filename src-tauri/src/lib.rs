pub mod ai;
pub mod commands;
pub mod core;
pub mod feeds;
pub mod glossary;
pub mod net;
pub mod store;
pub mod text;
pub mod themes;

use std::sync::Mutex;

use tauri::Manager;

use commands::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
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
            commands::enhance_story,
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
            commands::answer_quiz,
            commands::get_recap,
            commands::get_radar,
            commands::get_watchlist,
            commands::add_watch,
            commands::remove_watch,
            commands::list_sources,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
