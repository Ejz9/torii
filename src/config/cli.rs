
#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short = 'c', long = "config", default_value = "/etc/torii/config.toml")]
    config: String,
    #[command(subcommand)]
    command: Commands
}

#[derive(clap::Subcommand, Clone)]
enum Commands {
    Start,
    Reload
}