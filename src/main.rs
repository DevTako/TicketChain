use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ticket_chain::auth::{
    can, is_valid_nonce, now_secs, timestamp_in_window, Action, NonceCache, Registry, Role,
};
use ticket_chain::crypto::{signed_message, verify_hex};
use ticket_chain::{validate_ticket, Blockchain, Ticket};

const CHAIN_FILE: &str = "chain.json";
const USERS_FILE: &str = "users.json";

// ---------- Límites de red ----------

// El sobre firmado duplica el escapado del JSON interno, así que damos más margen que antes.
const MAX_LINE_BYTES: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 32;

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

// Todo el estado compartido en un solo lugar. Los dos Mutex nunca se toman a la vez
// (el de nonces se suelta antes de tomar el de la cadena), así que no hay interbloqueo.
struct Shared {
    chain: Mutex<Blockchain>,
    registry: Registry,
    nonces: Mutex<NonceCache>,
}

// ---------- Protocolo ----------

// Sobre: lo que llega por el cable.
#[derive(Deserialize)]
struct Envelope {
    user: String,
    ts: u64,
    nonce: String,
    payload: String,
    sig: String,
}

// Comando: lo que hay DENTRO del payload. Ya no incluye "reporter":
// lo decide el servidor según la identidad verificada.
#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "UPPERCASE")]
enum Request {
    Enviar {
        title: String,
        description: String,
        severity: String,
    },
    Listar,
    Validar,
}

fn error_json(message: &str) -> serde_json::Value {
    json!({"status": "error", "message": message})
}

const AUTH_FAILED: &str = "Autenticación fallida";

// Verifica el sobre. Devuelve (usuario, rol, payload) o el error para el cliente.
fn authenticate(line: &str, shared: &Shared) -> Result<(String, Role, String), String> {
    let env: Envelope =
        serde_json::from_str(line).map_err(|e| format!("Sobre inválido: {}", e))?;
    let now = now_secs();

    if !timestamp_in_window(env.ts, now) {
        return Err(String::from("Marca de tiempo fuera de ventana (revise el reloj)"));
    }
    if !is_valid_nonce(&env.nonce) {
        return Err(String::from("Nonce inválido"));
    }

    // Mismo mensaje para "usuario inexistente" y "firma incorrecta".
    let user = shared
        .registry
        .get(&env.user)
        .ok_or_else(|| AUTH_FAILED.to_string())?;
    let message = signed_message(&env.user, env.ts, &env.nonce, &env.payload);
    verify_hex(&user.public_key, &message, &env.sig).map_err(|_| AUTH_FAILED.to_string())?;

    // Solo tras verificar la firma registramos el nonce.
    let fresh = shared
        .nonces
        .lock()
        .expect("Mutex envenenado")
        .check_and_insert(&env.user, &env.nonce, env.ts, now);
    if !fresh {
        return Err(String::from("Petición repetida (replay) rechazada"));
    }

    Ok((user.user.clone(), user.role, env.payload))
}

fn process_request(line: &str, shared: &Shared, peer: &str) -> serde_json::Value {
    let (user, role, payload) = match authenticate(line, shared) {
        Ok(v) => v,
        Err(msg) => {
            println!("[!] {} rechazado: {}", peer, msg);
            return error_json(&msg);
        }
    };

    let request: Request = match serde_json::from_str(&payload) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("Comando inválido: {}", e)),
    };

    let cmd_name = match &request {
        Request::Enviar { .. } => "ENVIAR",
        Request::Listar => "LISTAR",
        Request::Validar => "VALIDAR",
    };
    println!("[>] {} ({:?}): {}", user, role, cmd_name);

    // Permisos y validación ANTES de tomar el candado de la cadena.
    if matches!(request, Request::Validar) && !can(role, Action::Validar) {
        println!("[!] {} sin permiso para {}", user, cmd_name);
        return error_json("Permiso denegado");
    }
    if let Request::Enviar { title, description, severity } = &request {
        // El reporter es el usuario autenticado, no un dato del cliente.
        if let Err(msg) = validate_ticket(title, description, &user, severity) {
            return error_json(&msg);
        }
    }

    let mut guard = shared.chain.lock().expect("Mutex envenenado");

    match request {
        Request::Enviar { title, description, severity } => {
            let ticket = Ticket { id: 0, title, description, reporter: user.clone(), severity };
            let index = guard.add_ticket(ticket);

            if let Err(e) = guard.save(CHAIN_FILE) {
                guard.blocks.pop();
                eprintln!("ERROR al persistir: {}", e);
                return error_json("No se pudo persistir el ticket");
            }

            let hash = guard.blocks[index as usize].hash.clone();
            json!({"status": "ok", "ticket_id": index, "hash": hash})
        }
        Request::Listar => {
            if can(role, Action::ListarTodo) {
                json!({"status": "ok", "blocks": guard.blocks})
            } else {
                // El reportante solo ve los tickets que él mismo envió.
                let own: Vec<_> = guard
                    .blocks
                    .iter()
                    .filter(|b| b.ticket.reporter == user)
                    .collect();
                json!({"status": "ok", "blocks": own})
            }
        }
        Request::Validar => match guard.is_valid() {
            Ok(()) => json!({"status": "ok", "valid": true}),
            Err(e) => json!({"status": "ok", "valid": false, "reason": e}),
        },
    }
}

// ---------- Red ----------

fn handle_client(stream: TcpStream, shared: Arc<Shared>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| String::from("desconocido"));
    println!("[+] Conectado: {}", peer);

    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
    {
        return;
    }

    let mut reader = BufReader::new(stream.try_clone().expect("No se pudo clonar el socket"));
    let mut writer = stream;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.clear();

        let result = (&mut reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf);

        match result {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
                    println!("[!] Timeout por inactividad: {}", peer);
                    let _ = writeln!(writer, "{}", error_json("Tiempo de inactividad agotado"));
                }
                break;
            }
        }

        if buf.last() != Some(&b'\n') {
            if buf.len() > MAX_LINE_BYTES {
                println!("[!] Petición demasiado grande, cerrando: {}", peer);
                let _ = writeln!(
                    writer,
                    "{}",
                    error_json(&format!("Petición excede {} bytes", MAX_LINE_BYTES))
                );
            }
            break;
        }

        let line = match std::str::from_utf8(&buf) {
            Ok(s) => s.trim(),
            Err(_) => {
                if writeln!(writer, "{}", error_json("La petición no es UTF-8 válido")).is_err() {
                    break;
                }
                continue;
            }
        };
        if line.is_empty() {
            continue;
        }

        let response = process_request(line, &shared, &peer);
        if writeln!(writer, "{}", response).is_err() {
            break;
        }
    }

    println!("[-] Desconectado: {}", peer);
}

fn main() {
    let chain = match Blockchain::open(CHAIN_FILE) {
        Ok(c) => {
            println!("Cadena cargada: {} bloques, integridad verificada", c.blocks.len());
            c
        }
        Err(e) => {
            eprintln!("ERROR CRÍTICO: {}", e);
            eprintln!("El servidor no iniciará con una cadena no verificada.");
            std::process::exit(1);
        }
    };

    let registry = match Registry::load(USERS_FILE) {
        Ok(r) => {
            println!("Registro de usuarios: {} usuarios cargados", r.len());
            r
        }
        Err(e) => {
            eprintln!("ERROR CRÍTICO: {}", e);
            eprintln!("El servidor no iniciará sin un registro de usuarios válido.");
            std::process::exit(1);
        }
    };

    let shared = Arc::new(Shared {
        chain: Mutex::new(chain),
        registry,
        nonces: Mutex::new(NonceCache::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:7878")
        .expect("No se pudo abrir el puerto 7878 (¿ya está en uso?)");
    println!("Servidor escuchando en 127.0.0.1:7878 (máx. {} conexiones)", MAX_CONNECTIONS);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let previous = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
                if previous >= MAX_CONNECTIONS {
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
                    println!("[!] Conexión rechazada: límite alcanzado");
                    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
                    let _ = writeln!(stream, "{}", error_json("Servidor ocupado, intente más tarde"));
                    continue;
                }

                let guard = ConnectionGuard;
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let _guard = guard;
                    handle_client(stream, shared);
                });
            }
            Err(e) => eprintln!("Error de conexión: {}", e),
        }
    }
}