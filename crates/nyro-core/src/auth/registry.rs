use std::sync::Arc;

use crate::auth::drivers::{
    ClaudeDriver, ClaudeSetupTokenDriver, GeminiCliDriver, OpenAIOAuthDriver, QwenCodeCliDriver,
};
use crate::auth::types::{AuthDriver, AuthDriverMetadata};

pub fn normalize_driver_key(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "openai-oauth" | "openai_oauth" | "openai" | "codex-cli" | "goodx" => "codex".to_string(),
        "cloud-code" | "cloud_code" | "gemini" | "google-code-assist" => "gemini-cli".to_string(),
        other => other.to_string(),
    }
}

pub fn build_driver(key: &str) -> Option<Arc<dyn AuthDriver>> {
    match normalize_driver_key(key).as_str() {
        "qwen-code-cli" => Some(Arc::new(QwenCodeCliDriver)),
        "claude" => Some(Arc::new(ClaudeDriver)),
        "claude-setup-token" => Some(Arc::new(ClaudeSetupTokenDriver)),
        "codex" => Some(Arc::new(OpenAIOAuthDriver)),
        "gemini-cli" => Some(Arc::new(GeminiCliDriver)),
        _ => None,
    }
}

pub fn list_driver_metadata() -> Vec<AuthDriverMetadata> {
    [
        build_driver("qwen-code-cli"),
        build_driver("claude"),
        build_driver("claude-setup-token"),
        build_driver("codex"),
        build_driver("gemini-cli"),
    ]
    .into_iter()
    .flatten()
    .map(|driver| driver.metadata())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{build_driver, list_driver_metadata, normalize_driver_key};

    #[test]
    fn normalizes_driver_keys() {
        assert_eq!(normalize_driver_key(" Gemini-CLI "), "gemini-cli");
    }

    #[test]
    fn builds_known_drivers() {
        let driver = build_driver("qwen-code-cli").expect("qwen driver");
        assert_eq!(driver.metadata().key, "qwen-code-cli");
    }

    #[test]
    fn lists_driver_metadata() {
        let keys = list_driver_metadata()
            .into_iter()
            .map(|item| item.key)
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                "qwen-code-cli",
                "claude",
                "claude-setup-token",
                "codex",
                "gemini-cli"
            ]
        );
    }
}
