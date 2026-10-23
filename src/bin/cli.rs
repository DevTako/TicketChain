use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use ticket_chain::auth::{is_valid_username, now_secs};
use ticket_chain::crypto::{load_signing_key, random_nonce_hex, sign_hex, signed_message};
use ticket_chain::paths;

const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

fn usage() -> ! {
    eprintln!("Uso (cli <usuario> <comando> ...):");
    eprintln!("  LISTAR");
    eprintln!("  VALIDAR");
    eprintln!("  ENVIAR \"<titulo>\" \"<descripcion>\" <severidad>");
    eprintln!("  ASIGNAR <ticket_id>");
    eprintln!("  RESOLVER <ticket_id> \"<nota>\"");
    eprintln!("  CREAR_USUARIO <nombre> <reportante|analista|admin>   (solo admin)");
    eprintln!("  LISTAR_USUARIOS                                       (solo admin)");
    eprintln!("Banderas de ataque (para demos): --replay | --forge | --stale");
    std::process::exit(2);
}

fn fail(msg: &str) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

fn parse_id(s: &str) -> u64 {
    match s.parse() {
        Ok(n) => n,
        Err(_) => fail("El ticket_id debe ser un número."),
    }
}

fn send_line(line: &str) -> Result<String, String> {
    let addr_str = paths::server_addr();
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("Dirección inválida '{}': {}", addr_str, e))?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("No se pudo conectar al servidor ({}): {}", addr_str, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;

    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    writer
        .write_all(line.as_bytes())
        .and_then(|_| writer.write_all(b"\n"))
        .map_err(|e| format!("Error al enviar: {}", e))?;

    let mut reader = BufReader::new(stream).take(MAX_RESPONSE_BYTES);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("Error al leer la respuesta: {}", e))?;
    Ok(response)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flags: Vec<&str> = args.iter().filter(|a| a.starts_with("--")).map(|a| a.as_str()).collect();
    let pos: Vec<&str> = args.iter().filter(|a| !a.starts_with("--")).map(|a| a.as_str()).collect();

    if pos.len() < 2 {
        usage();
    }
    let user = pos[0];
    if !is_valid_username(user) {
        fail("Nombre de usuario inválido.");
    }

    let payload = match pos[1].to_uppercase().as_str() {
        "LISTAR" => json!({"cmd": "LISTAR"}).to_string(),
        "VALIDAR" => json!({"cmd": "VALIDAR"}).to_string(),
        "ENVIAR" => {
            if pos.len() != 5 {
                usage();
            }
            json!({"cmd": "ENVIAR", "title": pos[2], "description": pos[3], "severity": pos[4]})
                .to_string()
        }
        "ASIGNAR" => {
            if pos.len() != 3 {
                usage();
            }
            json!({"cmd": "ASIGNAR", "ticket_id": parse_id(pos[2])}).to_string()
        }
        "RESOLVER" => {
            if pos.len() != 4 {
                usage();
            }
            json!({"cmd": "RESOLVER", "ticket_id": parse_id(pos[2]), "note": pos[3]}).to_string()
        }
        "CREAR_USUARIO" => {
            if pos.len() != 4 {
                usage();
            }
            json!({"cmd": "CREAR_USUARIO", "username": pos[2], "role": pos[3].to_lowercase()}).to_string()
        }
        "LISTAR_USUARIOS" => json!({"cmd": "LISTAR_USUARIOS"}).to_string(),
        _ => usage(),
    };

    let key_file = paths::key_path(user);
    let signing_key = match load_signing_key(&key_file) {
        Ok(k) => k,
        Err(e) => fail(&format!("No se pudo cargar la clave ({}): {}", key_file, e)),
    };

    // --stale: firma con una marca de tiempo de hace 5 minutos.
    let ts = if flags.contains(&"--stale") {
        now_secs().saturating_sub(300)
    } else {
        now_secs()
    };
    let nonce = match random_nonce_hex() {
        Ok(n) => n,
        Err(e) => fail(&e),
    };
    let signature = sign_hex(&signing_key, &signed_message(user, ts, &nonce, &payload));

    // --forge: firma un comando pero envía OTRO distinto.
    let sent_payload = if flags.contains(&"--forge") {
        json!({"cmd": "VALIDAR"}).to_string()
    } else {
        payload.clone()
    };

    let envelope = json!({
        "user": user, "ts": ts, "nonce": nonce, "payload": sent_payload, "sig": signature
    })
    .to_string();

    // --replay: reenvía exactamente el mismo sobre dos veces.
    let attempts = if flags.contains(&"--replay") { 2 } else { 1 };
    for i in 1..=attempts {
        match send_line(&envelope) {
            Ok(r) => println!("Respuesta {}: {}", i, r.trim()),
            Err(e) => fail(&e),
        }
    }
}
