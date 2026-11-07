//! Shell completions and man page generation.

use clap::{CommandFactory, ValueEnum};
use clap_complete::{generate, shells::Bash, shells::Fish, shells::Zsh};
use clap_mangen::Man;
use std::io::{self, Write};
use std::path::Path;

use crate::cli::Cli;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Fish,
    Zsh,
}

pub fn print_completions(shell: CompletionShell) -> io::Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    let mut stdout = io::stdout();
    match shell {
        CompletionShell::Bash => generate(Bash, &mut cmd, name, &mut stdout),
        CompletionShell::Fish => generate(Fish, &mut cmd, name, &mut stdout),
        CompletionShell::Zsh => generate(Zsh, &mut cmd, name, &mut stdout),
    }
    Ok(())
}

pub fn print_man_page() -> io::Result<()> {
    let cmd = Cli::command();
    let man = Man::new(cmd);
    let mut buf = Vec::new();
    man.render(&mut buf).map_err(|e| io::Error::other(e.to_string()))?;
    io::stdout().write_all(&buf)?;
    Ok(())
}

pub fn write_man_page(path: &Path) -> io::Result<()> {
    let cmd = Cli::command();
    let man = Man::new(cmd);
    let mut buf = Vec::new();
    man.render(&mut buf).map_err(|e| io::Error::other(e.to_string()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, buf)?;
    Ok(())
}
