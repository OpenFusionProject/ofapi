use std::{env::Args, process::exit};

use ofapi::tokens::{self, TokenCapabilities, TokenCapability};

fn print_usage() {
    println!("Usage: gen_token <command>");
    println!("Commands:");
    println!("\tgenerate <secret_path>");
    println!("\t\tGenerates a new token");
}

fn get_input(prompt: &str) -> String {
    println!("{}: ", prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap_or_else(|_| {
        println!("Canceled");
        exit(0);
    });
    input.trim().to_string()
}

const AVAILABLE_CAPABILITIES: &[TokenCapability] = &[
    TokenCapability::ApproveNames,
    TokenCapability::ManageAllAccounts,
];

fn list_caps(selected: &[TokenCapability]) {
    println!("Available capabilities:");
    for (n, cap) in AVAILABLE_CAPABILITIES.iter().enumerate() {
        let selected_str = if selected.contains(cap) { "[x]" } else { "[ ]" };
        println!("{} {:?} < {} >", selected_str, cap, n);
    }
}

fn gen_token(mut args: Args) -> Result<(), String> {
    let secret_path = args.next().ok_or("No secret path provided")?;
    let secret = std::fs::read(secret_path).map_err(|e| e.to_string())?;

    let subject = get_input("Enter an identifier for this token");

    let lifetime_secs = get_input("Enter the token lifetime in seconds (0 for permanent)")
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    let lifetime = if lifetime_secs == 0 {
        let response = get_input("Are you sure you want to create a permanent token? (y/n)");
        if response.trim().to_lowercase() != "y" {
            println!("Canceled");
            exit(0);
        }
        tokens::TokenLifetime::Permanent
    } else {
        tokens::TokenLifetime::Temporary(lifetime_secs)
    };

    let mut caps = Vec::new();
    loop {
        list_caps(&caps);
        let cap = get_input("Enter a token capability (or press enter to finish)");
        if cap.is_empty() {
            break;
        }
        let Ok(cap_index) = cap.parse::<usize>() else {
            println!("Invalid index");
            continue;
        };
        if cap_index >= AVAILABLE_CAPABILITIES.len() {
            println!("Invalid index");
            continue;
        }
        let selected_cap = AVAILABLE_CAPABILITIES[cap_index];
        if let Some(i) = caps.iter().position(|&c| c == selected_cap) {
            caps.remove(i);
        } else {
            caps.push(selected_cap);
        }
    }

    let caps = TokenCapabilities::from_vec(caps);
    let token = tokens::gen_jwt(&secret, subject, caps, lifetime)?;
    println!("Generated token: {}", token);

    Ok(())
}

/// Command line tool to generate a token
fn main() -> Result<(), String> {
    let mut args = std::env::args();
    args.next(); // skip the program name

    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "generate" => gen_token(args),
        _ => {
            print_usage();
            return Ok(());
        }
    }?;

    Ok(())
}
