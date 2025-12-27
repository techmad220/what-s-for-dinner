//! What's for Dinner - Rust Launcher with Python Plugin Support
//!
//! This launcher embeds the Python dinner app and supports plugins.

use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use include_dir::{include_dir, Dir};
use pyo3::prelude::*;
use pyo3::types::PyList;
use std::fs;
use std::path::PathBuf;

// Embed the dinner_app directory at compile time
static DINNER_APP: Dir = include_dir!("$CARGO_MANIFEST_DIR/../dinner_app");

/// Get the app data directory for storing extracted files and user data
fn get_app_dir() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "techmad", "WhatsForDinner")
        .context("Failed to determine app directories")?;

    let data_dir = proj_dirs.data_dir().to_path_buf();
    fs::create_dir_all(&data_dir)?;
    Ok(data_dir)
}

/// Get the plugins directory
fn get_plugins_dir() -> Result<PathBuf> {
    let app_dir = get_app_dir()?;
    let plugins_dir = app_dir.join("plugins");
    fs::create_dir_all(&plugins_dir)?;
    Ok(plugins_dir)
}

/// Extract embedded Python files to the app directory
fn extract_app_files(app_dir: &PathBuf) -> Result<PathBuf> {
    let dinner_app_dir = app_dir.join("dinner_app");

    // Always extract to ensure we have latest version
    fs::create_dir_all(&dinner_app_dir)?;

    fn extract_dir(dir: &Dir, target: &PathBuf) -> Result<()> {
        for file in dir.files() {
            let file_path = target.join(file.path().file_name().unwrap());
            fs::write(&file_path, file.contents())?;
        }
        for subdir in dir.dirs() {
            let subdir_path = target.join(subdir.path().file_name().unwrap());
            fs::create_dir_all(&subdir_path)?;
            extract_dir(subdir, &subdir_path)?;
        }
        Ok(())
    }

    extract_dir(&DINNER_APP, &dinner_app_dir)?;

    Ok(dinner_app_dir)
}

/// Load and execute plugins from the plugins directory
fn load_plugins(py: Python<'_>, plugins_dir: &PathBuf) -> PyResult<()> {
    if !plugins_dir.exists() {
        return Ok(());
    }

    // Add plugins dir to Python path
    let sys = py.import_bound("sys")?;
    let path = sys.getattr("path")?;
    let path: &Bound<'_, PyList> = path.downcast().map_err(|e| {
        pyo3::exceptions::PyTypeError::new_err(format!("Failed to get sys.path: {}", e))
    })?;
    path.insert(0, plugins_dir.to_str().unwrap())?;

    // Look for plugin files
    if let Ok(entries) = fs::read_dir(plugins_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "py") {
                let stem = path.file_stem().unwrap().to_str().unwrap();
                if stem.starts_with("plugin_") {
                    println!("Loading plugin: {}", stem);
                    if let Err(e) = py.import_bound(stem) {
                        eprintln!("Failed to load plugin {}: {}", stem, e);
                    }
                }
            }
        }
    }

    Ok(())
}

fn run_app() -> Result<()> {
    let app_dir = get_app_dir()?;
    let plugins_dir = get_plugins_dir()?;

    // Extract embedded Python files
    extract_app_files(&app_dir)?;

    Python::with_gil(|py| -> Result<()> {
        // Add app dir to Python path
        let sys = py.import_bound("sys").map_err(|e| anyhow!("Failed to import sys: {}", e))?;
        let path = sys.getattr("path").map_err(|e| anyhow!("Failed to get path: {}", e))?;
        let path: &Bound<'_, PyList> = path.downcast().map_err(|e| anyhow!("Failed to downcast path: {}", e))?;
        path.insert(0, app_dir.to_str().unwrap()).map_err(|e| anyhow!("Failed to insert path: {}", e))?;

        // Load plugins first
        load_plugins(py, &plugins_dir).map_err(|e| anyhow!("Failed to load plugins: {}", e))?;

        // Change working directory to where data files are
        std::env::set_current_dir(&app_dir)?;

        // Import and run the GUI
        let gui = py.import_bound("dinner_app.gui").map_err(|e| anyhow!("Failed to import gui: {}", e))?;
        gui.call_method0("run_app").map_err(|e| anyhow!("Failed to run app: {}", e))?;

        Ok(())
    })?;

    Ok(())
}

fn main() {
    if let Err(e) = run_app() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
