use anyhow::Context;
use serde::Serialize;

#[derive(clap::ValueEnum, Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Json,
    Pretty,
    Yaml,
}

pub fn print_data<T: Serialize>(value: &T, format: OutputFormat) -> anyhow::Result<()> {
    let rendered = match format {
        OutputFormat::Json => serde_json::to_string(value).context("serialize json")?,
        OutputFormat::Pretty => serde_json::to_string_pretty(value).context("serialize json")?,
        OutputFormat::Yaml => serde_yaml::to_string(value).context("serialize yaml")?,
    };
    println!("{rendered}");
    Ok(())
}
