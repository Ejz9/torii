use keidai::{ShinshiName, TunnelEndpoint};

use crate::ebpf::kekkai_manager::IpPrefix;

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short = 'c', long = "config", default_value = "/etc/torii/config.toml")]
    pub config: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Clone, serde::Serialize, serde::Deserialize)]
pub enum Commands {
    Start,
    Reload,
    #[command(arg_required_else_help = true)]
    Bans(BansArgs),
    ReloadThreats,
    Tunnel(TunnelArgs),
}

#[derive(clap::Args, Clone, serde::Serialize, serde::Deserialize)]
pub struct BansArgs {
    #[arg(short = 'a', long = "add", num_args = 1..)]
    pub add: Vec<IpPrefix>,
    #[arg(short = 'r', long = "remove", num_args = 1..)]
    pub remove: Vec<IpPrefix>,
    #[arg(short = 'l', long = "list", default_missing_value = "both")]
    pub list: Option<IpFilter>,
}

#[derive(clap::ValueEnum, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IpFilter {
    V4,
    V6,
    Both,
}

#[derive(clap::Args, Clone, serde::Serialize, serde::Deserialize)]
pub struct TunnelArgs {
    #[arg(short = 'n', long = "name")]
    pub name: Option<ShinshiName>,
    #[arg(short = 's', long = "server")]
    pub server: Option<TunnelEndpoint>,
}
