use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};

#[derive(clap::ValueEnum, Clone, Debug, Eq, PartialEq)]
pub enum CliTool {
    ClaudeCode,
    CodexCli,
    GeminiCli,
    Opencode,
}

impl CliTool {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::CodexCli => "codex-cli",
            Self::GeminiCli => "gemini-cli",
            Self::Opencode => "opencode",
        }
    }
    fn backup_key(&self) -> &'static str {
        self.as_str()
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct BackupStore(HashMap<String, HashMap<String, FileBackup>>);

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileBackup {
    existed: bool,
    content: Option<Vec<u8>>,
}

pub fn detect_cli_tools() -> anyhow::Result<HashMap<String, bool>> {
    let home = home_dir()?;
    Ok(HashMap::from([
        ("claude-code".to_string(), home.join(".claude").is_dir()),
        ("codex-cli".to_string(), home.join(".codex").is_dir()),
        ("gemini-cli".to_string(), home.join(".gemini").is_dir()),
        (
            "opencode".to_string(),
            home.join(".config").join("opencode").is_dir(),
        ),
    ]))
}

pub fn preview(tool: &CliTool, host: &str, api_key: &str, model: &str) -> String {
    match tool {
        CliTool::ClaudeCode => format!(
            "# ~/.claude/settings.json\n{{\n  \"env\": {{\n    \"ANTHROPIC_AUTH_TOKEN\": \"{api_key}\",\n    \"ANTHROPIC_BASE_URL\": \"{host}\",\n    \"ANTHROPIC_MODEL\": \"{model}\",\n    \"ANTHROPIC_DEFAULT_HAIKU_MODEL\": \"{model}\",\n    \"ANTHROPIC_DEFAULT_SONNET_MODEL\": \"{model}\",\n    \"ANTHROPIC_DEFAULT_OPUS_MODEL\": \"{model}\",\n    \"CLAUDE_CODE_NO_FLICKER\": \"1\"\n  }},\n  \"model\": \"{}\"\n}}",
            infer_claude_profile(model)
        ),
        CliTool::CodexCli => format!(
            "# ~/.codex/auth.json\n{{\n  \"OPENAI_API_KEY\": \"{api_key}\"\n}}\n\n# ~/.codex/config.toml\nmodel_provider = \"nyro\"\nmodel = \"{model}\"\nmodel_reasoning_effort = \"high\"\ndisable_response_storage = true\n\n[model_providers]\n[model_providers.nyro]\nname = \"Nyro Gateway\"\nbase_url = \"{host}/v1\"\nwire_api = \"responses\"\nrequires_openai_auth = true"
        ),
        CliTool::GeminiCli => format!(
            "# ~/.gemini/.env\nGEMINI_API_KEY={api_key}\nGEMINI_MODEL={model}\nGOOGLE_GEMINI_BASE_URL={host}\n\n# ~/.gemini/settings.json\n{{\n  \"security\": {{\n    \"auth\": {{\n      \"selectedType\": \"gemini-api-key\"\n    }}\n  }}\n}}"
        ),
        CliTool::Opencode => format!(
            "# ~/.config/opencode/opencode.json\n{{\n  \"$schema\": \"https://opencode.ai/config.json\",\n  \"model\": \"nyro/{model}\",\n  \"provider\": {{\n    \"nyro\": {{\n      \"name\": \"Nyro Gateway\",\n      \"npm\": \"@ai-sdk/openai-compatible\",\n      \"options\": {{\n        \"apiKey\": \"{api_key}\",\n        \"baseURL\": \"{host}/v1\",\n        \"model\": \"{model}\"\n      }},\n      \"models\": {{\n        \"{model}\": {{\n          \"name\": \"{model}\"\n        }}\n      }}\n    }}\n  }}\n}}"
        ),
    }
}

pub fn sync(tool: &CliTool, host: &str, api_key: &str, model: &str) -> anyhow::Result<Vec<String>> {
    let home = home_dir()?;
    let files = target_files(tool, &home);
    capture_backups(tool, &files)?;
    match tool {
        CliTool::ClaudeCode => sync_claude(&files[0], host, api_key, model)?,
        CliTool::CodexCli => sync_codex(&files[0], &files[1], &files[2], host, api_key, model)?,
        CliTool::GeminiCli => sync_gemini(&files[0], &files[1], host, api_key, model)?,
        CliTool::Opencode => sync_opencode(&files[0], host, api_key, model)?,
    }
    Ok(files
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| path.to_string_lossy().to_string())
        .collect())
}

pub fn restore(tool: &CliTool) -> anyhow::Result<Vec<String>> {
    let mut store = load_backup_store()?;
    let Some(saved) = store.0.remove(tool.backup_key()) else {
        return Ok(Vec::new());
    };
    let mut restored = Vec::new();
    for (path_str, backup) in saved {
        let path = PathBuf::from(&path_str);
        if backup.existed {
            let bytes = backup.content.unwrap_or_default();
            write_bytes(&path, &bytes)?;
        } else if path.exists() {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        }
        restored.push(path_str);
    }
    save_backup_store(&store)?;
    Ok(restored)
}

fn infer_claude_profile(model: &str) -> &'static str {
    let lower = model.to_ascii_lowercase();
    if lower.contains("haiku") {
        "haiku"
    } else if lower.contains("sonnet") {
        "sonnet"
    } else {
        "opus"
    }
}

fn sync_claude(path: &Path, host: &str, api_key: &str, model: &str) -> anyhow::Result<()> {
    let json = serde_json::json!({
        "env": {
            "ANTHROPIC_AUTH_TOKEN": api_key,
            "ANTHROPIC_BASE_URL": host,
            "ANTHROPIC_MODEL": model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
            "CLAUDE_CODE_NO_FLICKER": "1"
        },
        "model": infer_claude_profile(model)
    });
    write_json(path, &json)
}

fn sync_codex(
    auth_path: &Path,
    config_path: &Path,
    models_path: &Path,
    host: &str,
    api_key: &str,
    model: &str,
) -> anyhow::Result<()> {
    let auth = serde_json::json!({
        "OPENAI_API_KEY": api_key,
    });
    write_json(auth_path, &auth)?;
    let config = format!(
        "model_provider = \"nyro\"\nmodel = \"{model}\"\nmodel_reasoning_effort = \"high\"\ndisable_response_storage = true\n\n[model_providers]\n[model_providers.nyro]\nname = \"Nyro Gateway\"\nbase_url = \"{host}/v1\"\nwire_api = \"responses\"\nrequires_openai_auth = true\n"
    );
    write_text(config_path, &config)?;
    if models_path.exists() {
        fs::remove_file(models_path)
            .with_context(|| format!("remove {}", models_path.display()))?;
    }
    Ok(())
}

fn sync_gemini(
    env_path: &Path,
    settings_path: &Path,
    host: &str,
    api_key: &str,
    model: &str,
) -> anyhow::Result<()> {
    let env =
        format!("GEMINI_API_KEY={api_key}\nGEMINI_MODEL={model}\nGOOGLE_GEMINI_BASE_URL={host}\n");
    write_text(env_path, &env)?;
    let settings = serde_json::json!({
        "security": {"auth": {"selectedType": "gemini-api-key"}}
    });
    write_json(settings_path, &settings)
}

fn sync_opencode(path: &Path, host: &str, api_key: &str, model: &str) -> anyhow::Result<()> {
    let json = serde_json::json!({
        "$schema": "https://opencode.ai/config.json",
        "model": format!("nyro/{model}"),
        "provider": {
            "nyro": {
                "name": "Nyro Gateway",
                "npm": "@ai-sdk/openai-compatible",
                "options": {
                    "apiKey": api_key,
                    "baseURL": format!("{host}/v1"),
                    "model": model,
                },
                "models": {
                    model: {"name": model}
                }
            }
        }
    });
    write_json(path, &json)
}

fn target_files(tool: &CliTool, home: &Path) -> Vec<PathBuf> {
    match tool {
        CliTool::ClaudeCode => vec![home.join(".claude").join("settings.json")],
        CliTool::CodexCli => vec![
            home.join(".codex").join("auth.json"),
            home.join(".codex").join("config.toml"),
            home.join(".codex").join("models.json"),
        ],
        CliTool::GeminiCli => vec![
            home.join(".gemini").join(".env"),
            home.join(".gemini").join("settings.json"),
        ],
        CliTool::Opencode => vec![home.join(".config").join("opencode").join("opencode.json")],
    }
}

fn home_dir() -> anyhow::Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow!("failed to resolve home directory"))
}

fn backup_store_path() -> anyhow::Result<PathBuf> {
    Ok(home_dir()?.join(".nyro").join("cli-backups.json"))
}

fn load_backup_store() -> anyhow::Result<BackupStore> {
    let path = backup_store_path()?;
    if !path.exists() {
        return Ok(BackupStore::default());
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).context("parse cli backup store")
}

fn save_backup_store(store: &BackupStore) -> anyhow::Result<()> {
    let path = backup_store_path()?;
    write_json(&path, store)
}

fn capture_backups(tool: &CliTool, paths: &[PathBuf]) -> anyhow::Result<()> {
    let mut store = load_backup_store()?;
    if store.0.contains_key(tool.backup_key()) {
        return Ok(());
    }
    let mut saved = HashMap::new();
    for path in paths {
        let backup = if path.exists() {
            FileBackup {
                existed: true,
                content: Some(fs::read(path).with_context(|| format!("read {}", path.display()))?),
            }
        } else {
            FileBackup {
                existed: false,
                content: None,
            }
        };
        saved.insert(path.to_string_lossy().to_string(), backup);
    }
    store.0.insert(tool.backup_key().to_string(), saved);
    save_backup_store(&store)
}

fn write_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("serialize json")?;
    write_bytes(path, &bytes)
}

fn write_text(path: &Path, value: &str) -> anyhow::Result<()> {
    write_bytes(path, value.as_bytes())
}

fn write_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir -p {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}
