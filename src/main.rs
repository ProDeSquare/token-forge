use clap::{CommandFactory, Parser};
use std::process;
use token_forge::format_timestamp;
use token_forge::run_demo;
use token_forge::TokenForge;
use token_forge::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    if cli.command.is_none() {
        let mut cmd = Cli::command();
        cmd.print_help().unwrap();
        return;
    }

    let token_forge = match TokenForge::new() {
        Ok(tf) => tf,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    match cli.command.unwrap() {
        Commands::Generate {
            file,
            expiry,
            verbose,
        } => {
            if !file.exists() {
                eprintln!("Error: File '{}' does not exist", file.display());
                process::exit(1);
            }

            match token_forge.generate_from_file(&file, expiry) {
                Ok(token) => {
                    println!("{}", token);

                    if verbose {
                        match token_forge.verify_token(&token) {
                            Ok(claims) => {
                                println!("Issued at: {}", format_timestamp(claims.iat));

                                if let Some(exp) = claims.exp {
                                    println!("Expires at: {}", format_timestamp(exp));
                                }
                            }
                            Err(e) => {
                                eprintln!("Error parsing the token for verbose output: {}", e);
                                process::exit(1);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }

        Commands::Decode { token, verbose } => match token_forge.verify_token(&token) {
            Ok(claims) => match serde_json::to_string(&claims.payload) {
                Ok(json) => {
                    println!("{}", json);

                    if verbose {
                        println!("Issued at: {}", format_timestamp(claims.iat));

                        if let Some(exp) = claims.exp {
                            println!("Expires at: {}", format_timestamp(exp));
                        }
                    }
                }
                Err(_) => {
                    eprintln!("Error: Could not decode token");
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },

        Commands::Demo => {
            run_demo(&token_forge);
        }
    }
}
