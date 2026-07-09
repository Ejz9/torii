#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short = 'c', long = "config", default_value = "/etc/torii/config.toml")]
    pub config: String,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Clone)]
pub enum Commands {
    Start,
    Reload,
}
