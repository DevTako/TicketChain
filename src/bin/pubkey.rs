use ticket_chain::auth::is_valid_username;
use ticket_chain::crypto::{load_signing_key, public_key_hex};

fn main() {
    let user = match std::env::args().nth(1) {
        Some(u) if is_valid_username(&u) => u,
        _ => {
            eprintln!("Uso: cargo run --bin pubkey -- <usuario>");
            std::process::exit(2);
        }
    };

    match load_signing_key(&format!("keys/{}.key", user)) {
        Ok(sk) => println!("{}", public_key_hex(&sk)),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}