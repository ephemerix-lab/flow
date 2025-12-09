use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

mod capture;
mod cli;
mod crypto;
mod normalize;
mod pack;
mod replay;
mod util;
mod verify;

#[derive(Parser, Debug)]
#[command(
    name = "flow",
    version,
    about = "Deterministic HTTP record→replay→verify"
)]
struct Args {
    /// Override the default log level (info)
    #[arg(long = "log-level", value_enum, global = true, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
    /// Select the log output format
    #[arg(long = "log-format", value_enum, global = true, default_value_t = LogFormat::Auto)]
    log_format: LogFormat,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Record {
        #[arg(long)]
        out: String,
        #[arg(long, default_value = ":8080")]
        proxy: String,
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long, default_value = "52428800")]
        max_size: u64,
        #[arg(long, default_value_t = false)]
        intercept: bool,
        #[arg(long, hide = true)]
        exit_after: Option<usize>,
    },
    Pack {
        #[arg(long)]
        r#in: String,
        #[arg(long)]
        out: String,
        #[arg(long)]
        sign: Option<String>,
        #[arg(long, default_value_t = false)]
        deterministic: bool,
    },
    Replay {
        bundle: String,
        #[arg(long)]
        map: Vec<String>,
        #[arg(long, default_value_t = 1)]
        concurrency: usize,
    },
    Verify {
        bundle: String,
        #[arg(long)]
        policy: Option<String>,
        #[arg(long, default_value_t = false)]
        require_signature: bool,
    },
    Diff {
        a: String,
        b: String,
    },
    GenCert {
        #[arg(long, default_value = "flow-local")]
        cn: String,
    },
    Redact {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        r#in: String,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum LogFormat {
    Auto,
    Pretty,
    Json,
}

impl LogLevel {
    fn as_filter_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

fn init_logging(level: LogLevel, format: LogFormat) {
    use tracing_subscriber::{fmt, EnvFilter};

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_filter_str()));

    match format {
        LogFormat::Json => fmt().with_env_filter(env_filter.clone()).json().init(),
        LogFormat::Pretty => fmt().with_env_filter(env_filter.clone()).pretty().init(),
        LogFormat::Auto => fmt().with_env_filter(env_filter).init(),
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let Args {
        log_level,
        log_format,
        cmd,
    } = Args::parse();
    init_logging(log_level, log_format);
    match cmd {
        Command::Record {
            out,
            proxy,
            include,
            exclude,
            max_size,
            intercept,
            exit_after,
        } => {
            cli::cmd_record(
                out, proxy, include, exclude, max_size, intercept, exit_after,
            )
            .await
        }
        Command::Pack {
            r#in,
            out,
            sign,
            deterministic,
        } => cli::cmd_pack(r#in, out, sign, deterministic).await,
        Command::Replay {
            bundle,
            map,
            concurrency,
        } => cli::cmd_replay(bundle, map, concurrency).await,
        Command::Verify {
            bundle,
            policy,
            require_signature,
        } => cli::cmd_verify(bundle, policy, require_signature).await,
        Command::Diff { a, b } => cli::cmd_diff(a, b).await,
        Command::GenCert { cn } => cli::cmd_gen_cert(cn).await,
        Command::Redact { policy, r#in } => cli::cmd_redact(policy, r#in).await,
    }
}
