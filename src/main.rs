use anyhow::Result;
use clap::{Parser, Subcommand};
use rumsh::client::bootstrap::{SessionBootstrapper, parse_hex_key};
use rumsh::server::network::{
    bind_to_available_port_sync, determine_bind_address, parse_port_range,
};
use std::io::Write;
use std::net::ToSocketAddrs;

#[derive(Parser)]
#[command(name = "rumsh")]
#[command(about = "Rust Mobile Shell", long_about = None)]
struct Cli {
    /// Write log output to this file instead of stderr
    #[arg(short, long, global = true)]
    log_file: Option<String>,

    /// Enable debug logging to file (default log files if --log-file is not specified)
    #[arg(short, long, global = true)]
    debug: bool,

    /// Client mode: Server address (host:port) or SSH target (user@host)
    target: Option<String>,

    /// Client mode: Hexadecimal session key (for direct mode, omit for SSH bootstrap)
    #[arg(long, requires = "target")]
    key: Option<String>,

    /// Client mode: Port range to request on remote server (bootstrap mode only)
    #[arg(long, default_value = "60000:61000")]
    port_range: String,

    /// Client mode: Specific IP for the remote server to bind to (bootstrap mode only)
    #[arg(long)]
    remote_bind: Option<String>,

    /// Client mode: Path to rumsh binary on remote server
    #[arg(long, default_value = "rumsh")]
    remote_binary: String,

    /// Client mode: Path to log file on remote server (bootstrap mode only)
    #[arg(long)]
    remote_log_file: Option<String>,

    /// Client mode: Enable real-time debugging overlay in the top-right corner
    #[arg(short, long)]
    overlay: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start rumsh in server mode to accept connections
    Server {
        /// Specific IP address to bind to (overrides IP discovery)
        #[arg(long)]
        bind: Option<String>,

        /// Specific port to bind to (overrides port-range)
        #[arg(short, long)]
        port: Option<u16>,

        /// Port range to scan (format: start:end or start-end)
        #[arg(long, default_value = "60000:61000")]
        port_range: String,

        /// Bind to 0.0.0.0 instead of discovering IP via SSH_CONNECTION
        #[arg(long)]
        bind_any: bool,

        /// Do not daemonize (run in foreground, useful for debugging/testing)
        #[arg(long)]
        no_daemonize: bool,

        /// Shell to run (defaults to $SHELL, or /bin/bash)
        #[arg(short, long)]
        shell: Option<String>,
    },
}

fn run_server_subcommand(
    bind: Option<String>,
    port: Option<u16>,
    port_range: String,
    bind_any: bool,
    no_daemonize: bool,
    shell: Option<String>,
) -> Result<()> {
    let key = if let Ok(key_hex) = std::env::var("RUMSH_KEY") {
        parse_hex_key(&key_hex)?
    } else {
        rand::random()
    };

    let key_hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();

    // 1. Parse bind IP override if provided
    let bind_ip_override = if let Some(ref ip_str) = bind {
        Some(ip_str.parse::<std::net::IpAddr>()?)
    } else {
        None
    };

    // 2. Determine bind IP
    let bind_ip = determine_bind_address(bind_ip_override, bind_any);

    // 3. Determine port range
    let range = if let Some(p) = port {
        p..=p
    } else {
        parse_port_range(&port_range)?
    };

    // 4. Bind socket synchronously
    let (std_socket, bound_port) = bind_to_available_port_sync(bind_ip, range)?;

    // 5. Print Token to stdout (and flush!)
    let connect_token = format!("RUMSH CONNECT {} {}", bound_port, key_hex);
    println!("{}", connect_token);
    println!("RUMSH_PORT={}", bound_port);
    println!("RUMSH_KEY={}", key_hex);
    std::io::stdout().flush()?;

    log::info!("Server bootstrapped on IP {}, port {}", bind_ip, bound_port);

    // 6. Daemonize if requested
    if !no_daemonize {
        log::info!("Daemonizing server process...");
        let daemonize = daemonize::Daemonize::new()
            .working_directory("/tmp")
            .umask(0o077);

        match daemonize.start() {
            Ok(_) => {
                log::info!("Daemonized successfully. Child process running.");
            }
            Err(e) => {
                eprintln!("Error daemonizing: {}", e);
                std::process::exit(1);
            }
        }
    }

    // 7. Resolve Shell: Use $SHELL environment variable, fallback to /bin/bash
    let shell_path =
        shell.unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string()));

    log::info!(
        "Starting Rumsh Server on port {}, running shell {}",
        bound_port,
        shell_path
    );
    smol::block_on(rumsh::server::network::run_server(
        std_socket,
        &shell_path,
        key,
    ))?;
    Ok(())
}

fn run_client_mode(cli: Cli) -> Result<()> {
    let target_str = match cli.target {
        Some(ref t) => t,
        None => {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            return Err(anyhow::anyhow!(
                "Error: Positional argument <TARGET> or a subcommand (like 'server') is required."
            ));
        }
    };
    let overlay = cli.overlay;

    let (addr, key_bytes) = if let Some(ref key_str) = cli.key {
        // Direct mode (key is explicitly provided)
        let addr = target_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid server address"))?;
        let key_bytes = parse_hex_key(key_str)?;
        log::info!(
            "Starting Rumsh Client in direct mode, connecting to {}",
            addr
        );
        (addr, key_bytes)
    } else {
        // SSH Bootstrap mode
        let remote_log = if let Some(ref path) = cli.remote_log_file {
            Some(path.clone())
        } else if cli.debug {
            Some("/tmp/rumsh-server.log".to_string())
        } else {
            None
        };
        let bootstrapper = SessionBootstrapper::new(
            cli.remote_binary.clone(),
            cli.port_range.clone(),
            cli.remote_bind.clone(),
            remote_log,
        );
        bootstrapper.bootstrap(target_str)?
    };

    log::info!("Connecting to resolved UDP address: {}", addr);
    smol::block_on(rumsh::client::network::run_client(addr, key_bytes, overlay))?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_path = match cli.log_file {
        Some(ref path) => Some(std::path::PathBuf::from(path)),
        None if cli.debug => match cli.command {
            Some(Commands::Server { .. }) => Some(std::path::PathBuf::from("/tmp/rumsh-server.log")),
            None => Some(
                std::env::current_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
                    .join("rumsh-client.log"),
            ),
        },
        None => None,
    };

    if let Some(ref path) = log_path {
        // Ensure parent directory exists and open log file
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        let mut builder = env_logger::Builder::from_default_env();
        if std::env::var("RUST_LOG").is_err() {
            builder.filter_level(log::LevelFilter::Debug);
        }
        builder.target(env_logger::Target::Pipe(Box::new(file)));
        builder.init();

        log::info!("Logging initialized to file: {}", path.display());
    }

    match cli.command {
        Some(Commands::Server {
            bind,
            port,
            port_range,
            bind_any,
            no_daemonize,
            shell,
        }) => run_server_subcommand(bind, port, port_range, bind_any, no_daemonize, shell),
        None => run_client_mode(cli),
    }
}
