use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use crate::auth::{
    can, is_valid_nonce, now_secs, timestamp_in_window, Action, NonceCache, Registry, Role, User,
};
use crate::crypto::{
    generate_signing_key, public_key_hex, save_signing_key, signed_message, verify_hex,
};
use crate::paths;
use crate::{ticket_id_of, validate_command, Blockchain, Command, Proof};

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

pub struct ServerShared {
    pub chain: Mutex<Blockchain>,
    pub registry: RwLock<Registry>,
    pub nonces: Mutex<NonceCache>,
    pub chain_file: String,
    pub users_file: String,
}

#[derive(Deserialize)]
struct Envelope {
    user: String,
    ts: u64,
    nonce: String,
    payload: String,
    sig: String,
}

struct Authed {
    user: String,
    role: Role,
    proof: Proof,
}

fn error_json(message: &str) -> serde_json::Value {
    json!({"status": "error", "message": message})
}

const AUTH_FAILED: &str = "Autenticación fallida";

fn authenticate(line: &str, shared: &ServerShared) -> Result<Authed, String> {
    let env: Envelope =
        serde_json::from_str(line).map_err(|e| format!("Sobre inválido: {}", e))?;
    let now = now_secs();

    if !timestamp_in_window(env.ts, now) {
        return Err(String::from("Marca de tiempo fuera de ventana (revise el reloj)"));
    }
    if !is_valid_nonce(&env.nonce) {
        return Err(String::from("Nonce inválido"));
    }

    let (public_key, user_name, role) = {
        let registry = shared.registry.read().expect("RwLock envenenado");
        let user = registry.get(&env.user).ok_or_else(|| AUTH_FAILED.to_string())?;
        (user.public_key.clone(), user.user.clone(), user.role)
    };

    let message = signed_message(&user_name, env.ts, &env.nonce, &env.payload);
    verify_hex(&public_key, &message, &env.sig).map_err(|_| AUTH_FAILED.to_string())?;

    let fresh = shared
        .nonces
        .lock()
        .expect("Mutex envenenado")
        .check_and_insert(&user_name, &env.nonce, env.ts, now);
    if !fresh {
        return Err(String::from("Petición repetida (replay) rechazada"));
    }

    Ok(Authed {
        user: user_name,
        role,
        proof: Proof { ts: env.ts, nonce: env.nonce, payload: env.payload, sig: env.sig },
    })
}

fn process_request(line: &str, shared: &ServerShared, peer: &str) -> serde_json::Value {
    let auth = match authenticate(line, shared) {
        Ok(a) => a,
        Err(msg) => {
            println!("[!] {} rechazado: {}", peer, msg);
            return error_json(&msg);
        }
    };

    let cmd: Command = match serde_json::from_str(&auth.proof.payload) {
        Ok(c) => c,
        Err(e) => return error_json(&format!("Comando inválido: {}", e)),
    };

    let cmd_name = match &cmd {
        Command::Enviar { .. } => "ENVIAR",
        Command::Asignar { .. } => "ASIGNAR",
        Command::Resolver { .. } => "RESOLVER",
        Command::Listar => "LISTAR",
        Command::Validar => "VALIDAR",
        Command::CrearUsuario { .. } => "CREAR_USUARIO",
        Command::ListarUsuarios => "LISTAR_USUARIOS",
    };
    println!("[>] {} ({:?}): {}", auth.user, auth.role, cmd_name);

    let required: Option<Action> = match &cmd {
        Command::Enviar { .. } => Some(Action::Enviar),
        Command::Asignar { .. } => Some(Action::Asignar),
        Command::Resolver { .. } => Some(Action::Resolver),
        Command::Validar => Some(Action::Validar),
        Command::CrearUsuario { .. } => Some(Action::CrearUsuario),
        Command::ListarUsuarios => Some(Action::ListarUsuarios),
        Command::Listar => None,
    };
    if let Some(action) = required {
        if !can(auth.role, action) {
            println!("[!] {} sin permiso para {}", auth.user, cmd_name);
            return error_json("Permiso denegado");
        }
    }

    if let Err(msg) = validate_command(&cmd) {
        return error_json(&msg);
    }

    match &cmd {
        Command::Enviar { .. } | Command::Asignar { .. } | Command::Resolver { .. } => {
            let mut guard = shared.chain.lock().expect("Mutex envenenado");

            let index = match guard.append(&auth.user, auth.proof.clone(), &cmd) {
                Ok(i) => i,
                Err(msg) => {
                    println!("[!] {} rechazado por regla: {}", auth.user, msg);
                    return error_json(&msg);
                }
            };

            if let Err(e) = guard.save(&shared.chain_file) {
                guard.blocks.pop();
                eprintln!("ERROR al persistir: {}", e);
                return error_json("No se pudo persistir el evento");
            }

            let ticket_id = match &cmd {
                Command::Asignar { ticket_id } | Command::Resolver { ticket_id, .. } => *ticket_id,
                _ => index,
            };
            let hash = guard.blocks[index as usize].hash.clone();
            json!({"status": "ok", "block": index, "ticket_id": ticket_id, "hash": hash})
        }

        Command::Listar => {
            let guard = shared.chain.lock().expect("Mutex envenenado");
            let states = match guard.states() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ERROR: estado inconsistente: {}", e);
                    return error_json("Estado de la cadena inconsistente");
                }
            };

            let role_str = format!("{:?}", auth.role).to_lowercase();

            if can(auth.role, Action::ListarTodo) {
                let tickets: Vec<_> = states.values().collect();
                json!({"status": "ok", "role": role_str, "tickets": tickets, "blocks": guard.blocks})
            } else {
                let tickets: Vec<_> = states
                    .values()
                    .filter(|t| t.reporter == auth.user)
                    .collect();
                let own_ids: HashSet<u64> = tickets.iter().map(|t| t.id).collect();
                let blocks: Vec<_> = guard
                    .blocks
                    .iter()
                    .filter(|b| ticket_id_of(b).map_or(false, |id| own_ids.contains(&id)))
                    .collect();
                json!({"status": "ok", "role": role_str, "tickets": tickets, "blocks": blocks})
            }
        }

        Command::Validar => {
            let guard = shared.chain.lock().expect("Mutex envenenado");
            let registry = shared.registry.read().expect("RwLock envenenado");
            match guard.is_valid(&registry) {
                Ok(()) => json!({"status": "ok", "valid": true}),
                Err(e) => json!({"status": "ok", "valid": false, "reason": e}),
            }
        }

        Command::CrearUsuario { username, role } => {
            let parsed_role: Role = match role.as_str() {
                "reportante" => Role::Reportante,
                "analista" => Role::Analista,
                "admin" => Role::Admin,
                _ => return error_json("Rol inválido"),
            };

            let signing_key = match generate_signing_key() {
                Ok(k) => k,
                Err(e) => return error_json(&e),
            };
            let pubkey = public_key_hex(&signing_key);
            let privkey_hex = hex::encode(signing_key.to_bytes());

            let keys_dir = paths::keys_dir();
            if let Err(e) = std::fs::create_dir_all(&keys_dir) {
                return error_json(&format!("No se pudo crear directorio de claves: {}", e));
            }
            let key_file = paths::key_path(username);
            if let Err(e) = save_signing_key(&key_file, &signing_key) {
                return error_json(&format!("No se pudo guardar la clave: {}", e));
            }

            let new_user = User {
                user: username.clone(),
                role: parsed_role,
                public_key: pubkey.clone(),
            };

            let mut registry = shared.registry.write().expect("RwLock envenenado");
            if let Err(e) = registry.add_user(new_user) {
                let _ = std::fs::remove_file(&key_file);
                return error_json(&e);
            }
            if let Err(e) = registry.save(&shared.users_file) {
                return error_json(&format!("No se pudo persistir el registro: {}", e));
            }

            println!("[+] Usuario '{}' ({}) creado por {}", username, role, auth.user);
            json!({
                "status": "ok",
                "username": username,
                "role": role,
                "public_key": pubkey,
                "private_key": privkey_hex,
                "key_file": key_file,
            })
        }

        Command::ListarUsuarios => {
            let registry = shared.registry.read().expect("RwLock envenenado");
            let users: Vec<_> = registry.list_users();
            json!({"status": "ok", "users": users})
        }
    }
}

fn handle_client(stream: TcpStream, shared: Arc<ServerShared>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| String::from("desconocido"));

    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
    {
        return;
    }

    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
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
            Err(_) => break,
        }

        if buf.last() != Some(&b'\n') {
            break;
        }

        let line = match std::str::from_utf8(&buf) {
            Ok(s) => s.trim(),
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }

        let response = process_request(line, &shared, &peer);
        if writeln!(writer, "{}", response).is_err() {
            break;
        }
    }
}

pub fn start_server_listener(bind_addr: &str, chain_file: &str, users_file: &str) -> Result<(), String> {
    let registry = Registry::load(users_file)?;
    let chain = Blockchain::open(chain_file, &registry)?;

    let mut nonce_cache = NonceCache::new();
    let now = now_secs();
    for b in &chain.blocks {
        if let Some(p) = &b.proof {
            let _ = nonce_cache.check_and_insert(&b.actor, &p.nonce, p.ts, now);
        }
    }

    let shared = Arc::new(ServerShared {
        chain: Mutex::new(chain),
        registry: RwLock::new(registry),
        nonces: Mutex::new(nonce_cache),
        chain_file: chain_file.to_string(),
        users_file: users_file.to_string(),
    });

    let listener = TcpListener::bind(bind_addr)
        .map_err(|e| format!("No se pudo enlazar a {}: {}", bind_addr, e))?;
    println!("Servidor activo en {} (máx. {} conexiones)", bind_addr, MAX_CONNECTIONS);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let previous = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
                if previous >= MAX_CONNECTIONS {
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
                    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
                    let _ = writeln!(stream, "{}", error_json("Servidor ocupado"));
                    continue;
                }

                let guard = ConnectionGuard;
                let shared_clone = Arc::clone(&shared);
                thread::spawn(move || {
                    let _guard = guard;
                    handle_client(stream, shared_clone);
                });
            }
            Err(e) => eprintln!("Error de conexión: {}", e),
        }
    }
    Ok(())
}

/// Inicia el servidor en segundo plano si no hay ya uno escuchando en `bind_addr`.
/// El socket se enlaza sincrónicamente para garantizar que esté listo de inmediato.
pub fn ensure_server_running(bind_addr: &str, chain_file: &str, users_file: &str) {
    use std::net::SocketAddr;
    if let Ok(addr) = bind_addr.parse::<SocketAddr>() {
        // Si ya hay un servidor escuchando, no hace falta lanzar otro
        if TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok() {
            println!("[i] Servidor ya activo en {}", bind_addr);
            return;
        }
    }

    let listener = match TcpListener::bind(bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("No se pudo enlazar listener en {}: {}", bind_addr, e);
            return;
        }
    };

    let chain_path = chain_file.to_string();
    let users_path = users_file.to_string();

    thread::spawn(move || {
        let registry = match Registry::load(&users_path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error al cargar registro: {}", e);
                return;
            }
        };
        let chain = match Blockchain::open(&chain_path, &registry) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error al abrir blockchain: {}", e);
                return;
            }
        };

        let mut nonce_cache = NonceCache::new();
        let now = now_secs();
        for b in &chain.blocks {
            if let Some(p) = &b.proof {
                let _ = nonce_cache.check_and_insert(&b.actor, &p.nonce, p.ts, now);
            }
        }

        let shared = Arc::new(ServerShared {
            chain: Mutex::new(chain),
            registry: RwLock::new(registry),
            nonces: Mutex::new(nonce_cache),
            chain_file: chain_path,
            users_file: users_path,
        });

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let previous = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
                    if previous >= MAX_CONNECTIONS {
                        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
                        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
                        let _ = writeln!(stream, "{}", error_json("Servidor ocupado"));
                        continue;
                    }
                    let guard = ConnectionGuard;
                    let shared_clone = Arc::clone(&shared);
                    thread::spawn(move || {
                        let _guard = guard;
                        handle_client(stream, shared_clone);
                    });
                }
                Err(e) => eprintln!("Error de conexión: {}", e),
            }
        }
    });

    // 100 ms para permitir inicialización
    thread::sleep(Duration::from_millis(100));
}
