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
    Bans(BansArgs),
    Threats {
        #[arg(default_value = "refresh")]
        action: String,
    },
}

#[derive(clap::Args, Clone, serde::Serialize, serde::Deserialize)]
pub struct BansArgs {
    #[arg(short = 'a', long = "add", num_args = 1..)]
    pub add: Vec<String>,
    #[arg(short = 'r', long = "remove", num_args = 1..)]
    pub remove: Vec<String>,
    #[arg(short = 'l', long = "list", num_args = 0..=1, default_missing_value = "both")]
    pub list: Option<IpFilter>,
}

#[derive(clap::ValueEnum, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IpFilter {
    V4,
    V6,
    Both,
}
