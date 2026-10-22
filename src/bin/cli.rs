use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use ticket_chain::auth::{is_valid_username, now_secs};
use ticket_chain::crypto::{load_signing_key, random_nonce_hex, sign_hex, signed_message};

const SERVER_ADDR: &str = "127.0.0.1:7878";
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

fn usage() -> ! {
    eprintln!("Uso:");
    eprintln!("  cargo run --bin cli -- <usuario> LISTAR");
    eprintln!("  cargo run --bin cli -- <usuario> VALIDAR");
    eprintln!("  cargo run --bin cli -- <usuario> ENVIAR \"<titulo>\" \"<descripcion>\" <severidad>");
    eprintln!("Banderas de ataque (para demos): --replay | --forge | --stale");
    std::process::exit(2);
}

fn fail(msg: &str) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

fn send_line(line: &str) -> Result<String, String> {
    let addr: SocketAddr = SERVER_ADDR.parse().map_err(|e| format!("Dirección inválida: {}", e))?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("No se pudo conectar al servidor: {}", e))?;
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
        _ => usage(),
    };

    let signing_key = load_signing_key(&format!("keys/{}.key", user))
        .unwrap_or_else(|e| fail(&e));

    // --stale: firma con una marca de tiempo de hace 5 minutos.
    let ts = if flags.contains(&"--stale") {
        now_secs().saturating_sub(300)
    } else {
        now_secs()
    };
    let nonce = random_nonce_hex().unwrap_or_else(|e| fail(&e));
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