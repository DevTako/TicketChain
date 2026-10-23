use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::auth::{is_valid_username, now_secs};
use crate::crypto::{load_signing_key, random_nonce_hex, sign_hex, signed_message};
use crate::paths;

const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

fn send_line(line: &str) -> Result<String, String> {
    let addr_str = paths::server_addr();
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("Dirección inválida '{}': {}", addr_str, e))?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("No se pudo conectar al servidor ({}): {}", addr_str, e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

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

// Una sesión = un usuario con su clave privada cargada. Cada petición se firma.
pub struct Session {
    pub user: String,
    signing_key: SigningKey,
}

impl Session {
    pub fn open(user: &str) -> Result<Session, String> {
        if !is_valid_username(user) {
            return Err(String::from("Nombre de usuario inválido"));
        }
        let key_file = paths::key_path(user);
        let signing_key = load_signing_key(&key_file)?;
        Ok(Session { user: user.to_string(), signing_key })
    }

    // Firma y envía un payload. Devuelve Err con el mensaje del servidor si responde "error".
    pub fn request(&self, payload: &str) -> Result<Value, String> {
        let ts = now_secs();
        let nonce = random_nonce_hex()?;
        let sig = sign_hex(
            &self.signing_key,
            &signed_message(&self.user, ts, &nonce, payload),
        );
        let envelope = json!({
            "user": self.user, "ts": ts, "nonce": nonce, "payload": payload, "sig": sig
        })
        .to_string();

        let line = send_line(&envelope)?;
        let reply: Value =
            serde_json::from_str(&line).map_err(|e| format!("Respuesta inválida: {}", e))?;

        if reply["status"].as_str() == Some("ok") {
            Ok(reply)
        } else {
            Err(reply["message"]
                .as_str()
                .unwrap_or("Error desconocido")
                .to_string())
        }
    }

    pub fn listar(&self) -> Result<Value, String> {
        self.request(&json!({"cmd": "LISTAR"}).to_string())
    }

    pub fn validar(&self) -> Result<Value, String> {
        self.request(&json!({"cmd": "VALIDAR"}).to_string())
    }

    pub fn enviar(&self, title: &str, description: &str, severity: &str) -> Result<Value, String> {
        self.request(
            &json!({"cmd": "ENVIAR", "title": title, "description": description, "severity": severity})
                .to_string(),
        )
    }

    pub fn asignar(&self, ticket_id: u64) -> Result<Value, String> {
        self.request(&json!({"cmd": "ASIGNAR", "ticket_id": ticket_id}).to_string())
    }

    pub fn resolver(&self, ticket_id: u64, note: &str) -> Result<Value, String> {
        self.request(&json!({"cmd": "RESOLVER", "ticket_id": ticket_id, "note": note}).to_string())
    }

    pub fn crear_usuario(&self, username: &str, role: &str) -> Result<Value, String> {
        self.request(
            &json!({"cmd": "CREAR_USUARIO", "username": username, "role": role}).to_string(),
        )
    }

    pub fn listar_usuarios(&self) -> Result<Value, String> {
        self.request(&json!({"cmd": "LISTAR_USUARIOS"}).to_string())
    }
}

// Segundos desde 1970 -> "AAAA-MM-DD HH:MM:SS UTC".
pub fn format_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, m, d, secs / 3600, (secs % 3600) / 60, secs % 60
    )
}
