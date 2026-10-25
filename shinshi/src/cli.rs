use keidai::SidecarInit;

#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand)]
pub enum Commands {
    #[command(arg_required_else_help = true)]
    Start(StartArgs),
}

#[derive(clap::Args)]
pub struct StartArgs {
    #[arg(short, long, env = "SHINSHI_TOKEN")]
    pub token: Option<SidecarInit>,
    #[arg(long, default_value = "/etc/shinshi/token")]
    pub token_file: std::path::PathBuf,
}

impl StartArgs {
    pub fn load_token(&self) -> anyhow::Result<SidecarInit> {
        match &self.token {
            Some(init) => Ok(init.clone()),
            None => {
                let content = std::fs::read_to_string(&self.token_file).map_err(|e| {
                    anyhow::anyhow!(
                        "No token found via --token, SHINSHI_TOKEN, or {:?}: {e}",
                        self.token_file
                    )
                })?;
                content.trim().parse()
            }
        }
    }
}
