use clap::Args;
use serde::{ Serialize, Deserialize };
use super::options;


/// print shell complete rule
#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    /// shell type
    #[serde(skip, default = "default_shell")]
    shell: clap_complete::Shell
}

fn default_shell() -> clap_complete::Shell {
    clap_complete::Shell::Bash
}

impl Command {
    pub fn exec(self) -> anyhow::Result<()> {
        use std::io;
        use clap::CommandFactory;
    
        let mut cmd = options::Options::command();
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
    
        clap_complete::generate(self.shell, &mut cmd, "fi", &mut stdout);

        Ok(())
    }
}
