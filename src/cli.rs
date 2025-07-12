use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "tokenforge")]
#[command(about = "TokenForge - Token service")]
#[command(version = "1.0.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Generate {
        #[arg(short, long, help = "JSON file containing the payload")]
        file: PathBuf,

        #[arg(
            short,
            long,
            help = "Expiry time in seconds (optional, token never expires if not set)"
        )]
        expiry: Option<i64>,

        #[arg(
            short,
            long,
            help = "Show detailed information including issued at and expires at"
        )]
        verbose: bool,
    },

    Decode {
        #[arg(short, long, help = "Token to decode")]
        token: String,

        #[arg(
            short,
            long,
            help = "Show detailed information including issued at and expires at"
        )]
        verbose: bool,
    },

    Demo,
}
