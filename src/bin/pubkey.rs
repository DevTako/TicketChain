use ticket_chain::auth::is_valid_username;
use ticket_chain::crypto::{load_signing_key, public_key_hex};
use ticket_chain::paths;

fn main() {
    let user = match std::env::args().nth(1) {
        Some(u) if is_valid_username(&u) => u,
        _ => {
            eprintln!("Uso: pubkey <usuario>");
            std::process::exit(2);
        }
    };

    let key_file = paths::key_path(&user);
    match load_signing_key(&key_file) {
        Ok(sk) => println!("{}", public_key_hex(&sk)),
        Err(e) => {
            eprintln!("No se pudo leer la clave ({}): {}", key_file, e);
            std::process::exit(1);
        }
    }
}
