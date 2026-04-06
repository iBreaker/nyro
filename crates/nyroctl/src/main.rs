mod client;
mod connect;
mod output;

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use client::{AdminClient, ProxyClient};
use connect::CliTool;
use nyro_core::auth::{AuthExchangeInput, AuthSessionInitData, AuthSessionStatusData};
use nyro_core::db::models::{
    ApiKeyWithBindings, CreateApiKey, CreateProvider, CreateRoute, ExportData, ImportResult,
    LogPage, ModelCapabilities, ModelStats, Provider, ProviderStats, Route, StatsHourly,
    StatsOverview, TestResult, UpdateApiKey, UpdateProvider, UpdateRoute,
};
use output::{OutputFormat, print_data};
use serde::Serialize;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(name = "nyroctl", about = "Nyro headless control-plane CLI")]
struct Cli {
    #[arg(
        long,
        env = "NYRO_ADMIN_BASE_URL",
        default_value = "http://127.0.0.1:19552/api/v1"
    )]
    admin_base_url: String,
    #[arg(long, env = "NYRO_ADMIN_KEY")]
    admin_key: Option<String>,
    #[arg(
        long,
        env = "NYRO_PROXY_BASE_URL",
        default_value = "http://127.0.0.1:19550"
    )]
    proxy_base_url: String,
    #[arg(long, env = "NYRO_PROXY_API_KEY", default_value = "dummy")]
    proxy_api_key: String,
    #[arg(long, value_enum, default_value = "pretty")]
    output: OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Status,
    Providers {
        #[command(subcommand)]
        command: ProvidersCmd,
    },
    Routes {
        #[command(subcommand)]
        command: RoutesCmd,
    },
    #[command(name = "api-keys")]
    ApiKeys {
        #[command(subcommand)]
        command: ApiKeysCmd,
    },
    Oauth {
        #[command(subcommand)]
        command: OauthCmd,
    },
    Logs {
        #[command(subcommand)]
        command: LogsCmd,
    },
    Settings {
        #[command(subcommand)]
        command: SettingsCmd,
    },
    Export(ExportCmd),
    Import(ImportCmd),
    Request {
        #[command(subcommand)]
        command: RequestCmd,
    },
    Connect {
        #[command(subcommand)]
        command: ConnectCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ProvidersCmd {
    List,
    Get {
        id: String,
    },
    Presets,
    Create {
        #[arg(long)]
        file: PathBuf,
    },
    Update {
        id: String,
        #[arg(long)]
        file: PathBuf,
    },
    Delete {
        id: String,
    },
    Test {
        id: String,
    },
    #[command(name = "test-models")]
    TestModels {
        id: String,
    },
    Models {
        id: String,
    },
    Capabilities {
        id: String,
        #[arg(long)]
        model: String,
    },
    Oauth {
        id: String,
        #[command(subcommand)]
        command: ProvidersOauthCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ProvidersOauthCmd {
    Status,
    Reconnect,
    Logout,
}

#[derive(Subcommand, Debug)]
enum RoutesCmd {
    List,
    Get {
        id: String,
    },
    Create {
        #[arg(long)]
        file: PathBuf,
    },
    Update {
        id: String,
        #[arg(long)]
        file: PathBuf,
    },
    Delete {
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum ApiKeysCmd {
    List,
    Get {
        id: String,
    },
    Create {
        #[arg(long)]
        file: PathBuf,
    },
    Update {
        id: String,
        #[arg(long)]
        file: PathBuf,
    },
    Delete {
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum OauthCmd {
    Login(OauthLoginArgs),
    Init(OauthInitArgs),
    Status {
        session_id: String,
    },
    Cancel {
        session_id: String,
    },
    Complete {
        session_id: String,
        #[arg(long)]
        code: Option<String>,
        #[arg(long)]
        callback_url: Option<String>,
        #[arg(long)]
        metadata_file: Option<PathBuf>,
    },
    #[command(name = "create-provider")]
    CreateProvider {
        session_id: String,
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Args, Debug)]
struct OauthInitArgs {
    vendor: String,
    #[arg(long, default_value_t = false)]
    use_proxy: bool,
}

#[derive(Args, Debug)]
struct OauthLoginArgs {
    vendor: String,
    #[arg(long, default_value_t = false)]
    use_proxy: bool,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    no_open: bool,
    #[arg(long, default_value_t = false)]
    no_wait: bool,
    #[arg(long, default_value_t = 2)]
    poll_seconds: u64,
    #[arg(long, default_value_t = 600)]
    timeout_seconds: u64,
}

#[derive(Subcommand, Debug)]
enum LogsCmd {
    Query(LogsQueryArgs),
    Overview {
        #[arg(long)]
        hours: Option<i32>,
    },
    Hourly {
        #[arg(long, default_value_t = 24)]
        hours: i32,
    },
    Models {
        #[arg(long)]
        hours: Option<i32>,
    },
    Providers {
        #[arg(long)]
        hours: Option<i32>,
    },
}

#[derive(Args, Debug, Default)]
struct LogsQueryArgs {
    #[arg(long)]
    limit: Option<i64>,
    #[arg(long)]
    offset: Option<i64>,
    #[arg(long)]
    provider: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    status_min: Option<i32>,
    #[arg(long)]
    status_max: Option<i32>,
}

#[derive(Subcommand, Debug)]
enum SettingsCmd {
    List,
    Get { key: String },
    Set { key: String, value: String },
}

#[derive(Args, Debug)]
struct ExportCmd {
    #[arg(long)]
    output_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ImportCmd {
    #[arg(long)]
    file: PathBuf,
}

#[derive(Subcommand, Debug)]
enum RequestCmd {
    Test(RequestTestArgs),
    Chat(RequestChatArgs),
    Messages(RequestMessagesArgs),
    #[command(name = "tool-test")]
    ToolTest(RequestToolTestArgs),
}

#[derive(Args, Debug)]
struct RequestTestArgs {
    #[arg(long)]
    model: String,
    #[arg(long)]
    input: String,
    #[arg(long, default_value_t = false)]
    stream: bool,
}

#[derive(Args, Debug)]
struct RequestChatArgs {
    #[arg(long)]
    model: String,
    #[arg(long)]
    prompt: String,
    #[arg(long, default_value_t = false)]
    stream: bool,
}

#[derive(Args, Debug)]
struct RequestMessagesArgs {
    #[arg(long)]
    model: String,
    #[arg(long)]
    prompt: String,
    #[arg(long, default_value_t = 256)]
    max_tokens: i32,
    #[arg(long, default_value_t = false)]
    stream: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Eq, PartialEq)]
enum ToolTestProtocol {
    Responses,
    Messages,
}

#[derive(Args, Debug)]
struct RequestToolTestArgs {
    #[arg(long)]
    model: String,
    #[arg(long, default_value = "What is 2+3? Use the tool.")]
    prompt: String,
    #[arg(long, value_enum, default_value = "responses")]
    protocol: ToolTestProtocol,
    #[arg(long, default_value_t = false)]
    stream: bool,
}

#[derive(Subcommand, Debug)]
enum ConnectCmd {
    Detect,
    Preview(ConnectPreviewArgs),
    Sync(ConnectPreviewArgs),
    Restore { tool: CliTool },
}

#[derive(Args, Debug)]
struct ConnectPreviewArgs {
    tool: CliTool,
    #[arg(long)]
    host: String,
    #[arg(long)]
    api_key: String,
    #[arg(long)]
    model: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let admin = AdminClient::new(cli.admin_base_url.clone(), cli.admin_key.clone());

    match cli.command {
        Command::Status => {
            let value: Value = admin.get("/status").await?;
            print_data(&value, cli.output)?;
        }
        Command::Providers { command } => match command {
            ProvidersCmd::List => {
                print_data(&admin.get::<Vec<Provider>>("/providers").await?, cli.output)?
            }
            ProvidersCmd::Get { id } => print_data(
                &admin.get::<Provider>(&format!("/providers/{id}")).await?,
                cli.output,
            )?,
            ProvidersCmd::Presets => print_data(
                &admin.get::<Vec<Value>>("/providers/presets").await?,
                cli.output,
            )?,
            ProvidersCmd::Create { file } => {
                let body: CreateProvider = load_data_file(&file)?;
                print_data(
                    &admin.post::<_, Provider>("/providers", &body).await?,
                    cli.output,
                )?;
            }
            ProvidersCmd::Update { id, file } => {
                let body: UpdateProvider = load_data_file(&file)?;
                print_data(
                    &admin
                        .put::<_, Provider>(&format!("/providers/{id}"), &body)
                        .await?,
                    cli.output,
                )?;
            }
            ProvidersCmd::Delete { id } => print_data(
                &admin.delete::<Value>(&format!("/providers/{id}")).await?,
                cli.output,
            )?,
            ProvidersCmd::Test { id } => print_data(
                &admin
                    .get::<TestResult>(&format!("/providers/{id}/test"))
                    .await?,
                cli.output,
            )?,
            ProvidersCmd::TestModels { id } => print_data(
                &admin
                    .get::<Vec<String>>(&format!("/providers/{id}/test-models"))
                    .await?,
                cli.output,
            )?,
            ProvidersCmd::Models { id } => print_data(
                &admin
                    .get::<Vec<String>>(&format!("/providers/{id}/models"))
                    .await?,
                cli.output,
            )?,
            ProvidersCmd::Capabilities { id, model } => print_data(
                &admin
                    .get::<ModelCapabilities>(&format!(
                        "/providers/{id}/model-capabilities?model={}",
                        url_encode(&model)
                    ))
                    .await?,
                cli.output,
            )?,
            ProvidersCmd::Oauth { id, command } => match command {
                ProvidersOauthCmd::Status => print_data(
                    &admin
                        .get::<Value>(&format!("/providers/{id}/oauth/status"))
                        .await?,
                    cli.output,
                )?,
                ProvidersOauthCmd::Reconnect => print_data(
                    &admin
                        .post::<_, Value>(
                            &format!("/providers/{id}/oauth/reconnect"),
                            &serde_json::json!({}),
                        )
                        .await?,
                    cli.output,
                )?,
                ProvidersOauthCmd::Logout => print_data(
                    &admin
                        .post::<_, Value>(
                            &format!("/providers/{id}/oauth/logout"),
                            &serde_json::json!({}),
                        )
                        .await?,
                    cli.output,
                )?,
            },
        },
        Command::Routes { command } => match command {
            RoutesCmd::List => print_data(&admin.get::<Vec<Route>>("/routes").await?, cli.output)?,
            RoutesCmd::Get { id } => print_data(
                &admin.get::<Route>(&format!("/routes/{id}")).await?,
                cli.output,
            )?,
            RoutesCmd::Create { file } => {
                let body: CreateRoute = load_data_file(&file)?;
                print_data(&admin.post::<_, Route>("/routes", &body).await?, cli.output)?;
            }
            RoutesCmd::Update { id, file } => {
                let body: UpdateRoute = load_data_file(&file)?;
                print_data(
                    &admin
                        .put::<_, Route>(&format!("/routes/{id}"), &body)
                        .await?,
                    cli.output,
                )?;
            }
            RoutesCmd::Delete { id } => print_data(
                &admin.delete::<Value>(&format!("/routes/{id}")).await?,
                cli.output,
            )?,
        },
        Command::ApiKeys { command } => match command {
            ApiKeysCmd::List => print_data(
                &admin.get::<Vec<ApiKeyWithBindings>>("/api-keys").await?,
                cli.output,
            )?,
            ApiKeysCmd::Get { id } => print_data(
                &admin
                    .get::<ApiKeyWithBindings>(&format!("/api-keys/{id}"))
                    .await?,
                cli.output,
            )?,
            ApiKeysCmd::Create { file } => {
                let body: CreateApiKey = load_data_file(&file)?;
                print_data(
                    &admin
                        .post::<_, ApiKeyWithBindings>("/api-keys", &body)
                        .await?,
                    cli.output,
                )?;
            }
            ApiKeysCmd::Update { id, file } => {
                let body: UpdateApiKey = load_data_file(&file)?;
                print_data(
                    &admin
                        .put::<_, ApiKeyWithBindings>(&format!("/api-keys/{id}"), &body)
                        .await?,
                    cli.output,
                )?;
            }
            ApiKeysCmd::Delete { id } => print_data(
                &admin.delete::<Value>(&format!("/api-keys/{id}")).await?,
                cli.output,
            )?,
        },
        Command::Oauth { command } => match command {
            OauthCmd::Login(args) => {
                let provider = run_interactive_oauth_login(&admin, args).await?;
                print_data(&provider, cli.output)?;
            }
            OauthCmd::Init(args) => {
                let body = serde_json::json!({"vendor": args.vendor, "use_proxy": args.use_proxy});
                print_data(
                    &admin
                        .post::<_, AuthSessionInitData>("/oauth/sessions/init", &body)
                        .await?,
                    cli.output,
                )?;
            }
            OauthCmd::Status { session_id } => print_data(
                &admin
                    .get::<AuthSessionStatusData>(&format!("/oauth/sessions/{session_id}/status"))
                    .await?,
                cli.output,
            )?,
            OauthCmd::Cancel { session_id } => print_data(
                &admin
                    .post::<_, Value>(
                        &format!("/oauth/sessions/{session_id}/cancel"),
                        &serde_json::json!({}),
                    )
                    .await?,
                cli.output,
            )?,
            OauthCmd::Complete {
                session_id,
                code,
                callback_url,
                metadata_file,
            } => {
                let metadata = if let Some(path) = metadata_file {
                    load_data_file::<Value>(&path)?
                } else {
                    serde_json::json!({})
                };
                let body = AuthExchangeInput {
                    code,
                    callback_url,
                    metadata,
                };
                print_data(
                    &admin
                        .post::<_, Value>(&format!("/oauth/sessions/{session_id}/complete"), &body)
                        .await?,
                    cli.output,
                )?;
            }
            OauthCmd::CreateProvider { session_id, file } => {
                let input: CreateProvider = load_data_file(&file)?;
                let body = serde_json::json!({"session_id": session_id, "input": input});
                print_data(
                    &admin.post::<_, Provider>("/providers/oauth", &body).await?,
                    cli.output,
                )?;
            }
        },
        Command::Logs { command } => match command {
            LogsCmd::Query(args) => {
                let query = build_log_query(args);
                print_data(
                    &admin.get::<LogPage>(&format!("/logs{}", query)).await?,
                    cli.output,
                )?;
            }
            LogsCmd::Overview { hours } => print_data(
                &admin
                    .get::<StatsOverview>(&with_hours("/stats/overview", hours))
                    .await?,
                cli.output,
            )?,
            LogsCmd::Hourly { hours } => print_data(
                &admin
                    .get::<Vec<StatsHourly>>(&format!("/stats/hourly?hours={hours}"))
                    .await?,
                cli.output,
            )?,
            LogsCmd::Models { hours } => print_data(
                &admin
                    .get::<Vec<ModelStats>>(&with_hours("/stats/models", hours))
                    .await?,
                cli.output,
            )?,
            LogsCmd::Providers { hours } => print_data(
                &admin
                    .get::<Vec<ProviderStats>>(&with_hours("/stats/providers", hours))
                    .await?,
                cli.output,
            )?,
        },
        Command::Settings { command } => match command {
            SettingsCmd::List => print_data(
                &admin.get::<Vec<(String, String)>>("/settings").await?,
                cli.output,
            )?,
            SettingsCmd::Get { key } => print_data(
                &admin
                    .get::<Option<String>>(&format!("/settings/{key}"))
                    .await?,
                cli.output,
            )?,
            SettingsCmd::Set { key, value } => print_data(
                &admin
                    .put::<_, Value>(
                        &format!("/settings/{key}"),
                        &serde_json::json!({"value": value}),
                    )
                    .await?,
                cli.output,
            )?,
        },
        Command::Export(args) => {
            let data = admin.get::<ExportData>("/config/export").await?;
            if let Some(path) = args.output_file {
                write_output_file(&path, &data, cli.output)?;
            } else {
                print_data(&data, cli.output)?;
            }
        }
        Command::Import(args) => {
            let data: ExportData = load_data_file(&args.file)?;
            print_data(
                &admin
                    .post::<_, ImportResult>("/config/import", &data)
                    .await?,
                cli.output,
            )?;
        }
        Command::Request { command } => {
            let proxy = ProxyClient::new(cli.proxy_base_url, cli.proxy_api_key);
            match command {
                RequestCmd::Test(args) => {
                    let body = serde_json::json!({
                        "model": args.model,
                        "input": args.input,
                        "stream": args.stream,
                    });
                    let value: Value = proxy.responses(&body).await?;
                    print_data(&value, cli.output)?;
                }
                RequestCmd::Chat(args) => {
                    let body = serde_json::json!({
                        "model": args.model,
                        "messages": [
                            {
                                "role": "user",
                                "content": args.prompt
                            }
                        ],
                        "stream": args.stream,
                    });
                    let value: Value = proxy.chat_completions(&body).await?;
                    print_data(&value, cli.output)?;
                }
                RequestCmd::Messages(args) => {
                    let body = serde_json::json!({
                        "model": args.model,
                        "messages": [
                            {
                                "role": "user",
                                "content": args.prompt
                            }
                        ],
                        "max_tokens": args.max_tokens,
                        "stream": args.stream,
                    });
                    let value: Value = proxy.messages(&body).await?;
                    print_data(&value, cli.output)?;
                }
                RequestCmd::ToolTest(args) => {
                    let value = run_tool_test(&proxy, args).await?;
                    print_data(&value, cli.output)?;
                }
            }
        }
        Command::Connect { command } => match command {
            ConnectCmd::Detect => print_data(&connect::detect_cli_tools()?, cli.output)?,
            ConnectCmd::Preview(args) => println!(
                "{}",
                connect::preview(&args.tool, &args.host, &args.api_key, &args.model)
            ),
            ConnectCmd::Sync(args) => print_data(
                &connect::sync(&args.tool, &args.host, &args.api_key, &args.model)?,
                cli.output,
            )?,
            ConnectCmd::Restore { tool } => print_data(&connect::restore(&tool)?, cli.output)?,
        },
    }

    Ok(())
}

async fn run_interactive_oauth_login(admin: &AdminClient, args: OauthLoginArgs) -> anyhow::Result<Value> {
    let body = serde_json::json!({"vendor": args.vendor, "use_proxy": args.use_proxy});
    let init = admin
        .post::<_, AuthSessionInitData>("/oauth/sessions/init", &body)
        .await?;

    eprintln!("OAuth session: {}", init.session_id);
    eprintln!("Vendor: {}", init.vendor);
    eprintln!("Open this URL and complete login:");
    eprintln!("{}", init.auth_url);
    if !init.user_code.trim().is_empty() {
        eprintln!("User code: {}", init.user_code);
    }
    if !args.no_open {
        match open_in_browser(&init.auth_url) {
            Ok(()) => eprintln!("Opened browser."),
            Err(err) => eprintln!("Could not open browser automatically: {err}"),
        }
    }

    let ready = if args.no_wait {
        admin.get::<AuthSessionStatusData>(&format!("/oauth/sessions/{}/status", init.session_id))
            .await?
    } else if init.requires_manual_code {
        anyhow::ensure!(
            io::stdin().is_terminal(),
            "interactive oauth login needs a terminal; otherwise use `oauth complete` manually"
        );
        eprintln!("After browser login, paste the full callback URL or the authorization code.");
        let pasted = prompt_line("callback URL or code")?;
        let trimmed = pasted.trim();
        let (callback_url, code) =
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                (Some(trimmed.to_string()), None)
            } else {
                (None, Some(trimmed.to_string()))
            };
        admin.post::<_, AuthSessionStatusData>(
            &format!("/oauth/sessions/{}/complete", init.session_id),
            &AuthExchangeInput {
                code,
                callback_url,
                metadata: serde_json::json!({}),
            },
        )
        .await?
    } else {
        poll_oauth_until_ready(admin, &init.session_id, args.poll_seconds, args.timeout_seconds)
            .await?
    };

    let ready_json = serde_json::to_value(&ready)?;
    if let Some(file) = args.file {
        let input: CreateProvider = load_data_file(&file)?;
        let body = serde_json::json!({"session_id": init.session_id, "input": input});
        let provider = admin.post::<_, Provider>("/providers/oauth", &body).await?;
        return serde_json::to_value(provider).context("serialize provider result");
    }

    let payload = serde_json::json!({
        "session_id": init.session_id,
        "result": ready_json,
    });
    Ok(payload)
}

async fn poll_oauth_until_ready(
    admin: &AdminClient,
    session_id: &str,
    poll_seconds: u64,
    timeout_seconds: u64,
) -> anyhow::Result<AuthSessionStatusData> {
    let started = std::time::Instant::now();
    let sleep_for = Duration::from_secs(poll_seconds.max(1));

    loop {
        let status = admin
            .get::<AuthSessionStatusData>(&format!("/oauth/sessions/{session_id}/status"))
            .await?;
        match &status {
            AuthSessionStatusData::Pending {
                expires_in,
                interval,
                ..
            } => {
                eprintln!(
                    "Waiting for authorization... expires_in={}s next_poll={}s",
                    expires_in, interval
                );
            }
            AuthSessionStatusData::Ready { .. } => return Ok(status),
            AuthSessionStatusData::Error { code, message } => {
                anyhow::bail!("{code}: {message}");
            }
        }

        if started.elapsed() >= Duration::from_secs(timeout_seconds.max(1)) {
            anyhow::bail!("oauth login timed out after {}s", timeout_seconds.max(1));
        }
        tokio::time::sleep(sleep_for).await;
    }
}

fn prompt_line(label: &str) -> anyhow::Result<String> {
    eprint!("{label}> ");
    io::stderr().flush().context("flush prompt")?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).context("read stdin")?;
    let value = line.trim().to_string();
    if value.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    Ok(value)
}

fn open_in_browser(url: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    let candidates: &[(&str, &[&str])] = &[("open", &[])];
    #[cfg(target_os = "windows")]
    let candidates: &[(&str, &[&str])] = &[("cmd", &["/C", "start", ""])];
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let candidates: &[(&str, &[&str])] = &[("xdg-open", &[])];

    for (program, args) in candidates {
        let status = ProcessCommand::new(program).args(*args).arg(url).status();
        if let Ok(status) = status {
            if status.success() {
                return Ok(());
            }
        }
    }

    anyhow::bail!("no browser opener succeeded")
}

fn load_data_file<T: serde::de::DeserializeOwned>(path: &PathBuf) -> anyhow::Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
    {
        "yaml" | "yml" => serde_yaml::from_slice(&bytes).context("parse yaml file"),
        _ => serde_json::from_slice(&bytes)
            .or_else(|_| serde_yaml::from_slice(&bytes))
            .context("parse json/yaml file"),
    }
}

fn write_output_file<T: Serialize>(
    path: &PathBuf,
    value: &T,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let rendered = match format {
        OutputFormat::Json => serde_json::to_string(value).context("serialize json")?,
        OutputFormat::Pretty => serde_json::to_string_pretty(value).context("serialize json")?,
        OutputFormat::Yaml => serde_yaml::to_string(value).context("serialize yaml")?,
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir -p {}", parent.display()))?;
    }
    fs::write(path, rendered).with_context(|| format!("write {}", path.display()))
}

fn build_log_query(args: LogsQueryArgs) -> String {
    let mut params = Vec::new();
    push_query(&mut params, "limit", args.limit.map(|v| v.to_string()));
    push_query(&mut params, "offset", args.offset.map(|v| v.to_string()));
    push_query(&mut params, "provider", args.provider);
    push_query(&mut params, "model", args.model);
    push_query(
        &mut params,
        "status_min",
        args.status_min.map(|v| v.to_string()),
    );
    push_query(
        &mut params,
        "status_max",
        args.status_max.map(|v| v.to_string()),
    );
    if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    }
}

fn with_hours(base: &str, hours: Option<i32>) -> String {
    match hours {
        Some(hours) => format!("{base}?hours={hours}"),
        None => base.to_string(),
    }
}

fn push_query(params: &mut Vec<String>, key: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        params.push(format!("{}={}", key, url_encode(&value)));
    }
}

fn url_encode(value: &str) -> String {
    let mut encoded = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(b))
            }
            _ => encoded.push_str(&format!("%{:02X}", b)),
        }
    }
    encoded
}

async fn run_tool_test(proxy: &ProxyClient, args: RequestToolTestArgs) -> anyhow::Result<Value> {
    match args.protocol {
        ToolTestProtocol::Responses => {
            let body = serde_json::json!({
                "model": args.model,
                "input": args.prompt,
                "stream": args.stream,
                "tools": [
                    {
                        "type": "function",
                        "name": "add_numbers",
                        "description": "Add two integers",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "a": {"type": "integer"},
                                "b": {"type": "integer"}
                            },
                            "required": ["a", "b"]
                        }
                    }
                ]
            });
            proxy.responses(&body).await
        }
        ToolTestProtocol::Messages => {
            let body = serde_json::json!({
                "model": args.model,
                "max_tokens": 128,
                "stream": args.stream,
                "messages": [
                    {
                        "role": "user",
                        "content": args.prompt
                    }
                ],
                "tools": [
                    {
                        "name": "add_numbers",
                        "description": "Add two integers",
                        "input_schema": {
                            "type": "object",
                            "properties": {
                                "a": {"type": "integer"},
                                "b": {"type": "integer"}
                            },
                            "required": ["a", "b"]
                        }
                    }
                ]
            });
            proxy.messages(&body).await
        }
    }
}
