use std::fs;
use ticket_chain::crypto::{generate_signing_key, public_key_hex, save_signing_key};

fn main() {
    let user = match std::env::args().nth(1) {
        Some(u) => u,
        None => {
            eprintln!("Uso: cargo run --bin keygen -- <usuario>");
            std::process::exit(2);
        }
    };

    // El nombre se usa en una ruta de archivo: lista blanca estricta para impedir
    // trucos como "..\\..\\algo" (path traversal).
    let valid = !user.is_empty()
        && user.len() <= 32
        && user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid {
        eprintln!("Nombre inválido: use solo letras, números, '_' y '-' (máx. 32).");
        std::process::exit(2);
    }

    if let Err(e) = fs::create_dir_all("keys") {
        eprintln!("No se pudo crear la carpeta keys: {}", e);
        std::process::exit(1);
    }

    let path = format!("keys/{}.key", user);
    let signing_key = match generate_signing_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = save_signing_key(&path, &signing_key) {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    println!("Clave privada guardada en: {}  (NO la compartas ni la subas a Git)", path);
    println!("Clave pública de {}: {}", user, public_key_hex(&signing_key));
}