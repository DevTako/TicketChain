pub mod auth;
pub mod client;
pub mod crypto;
pub mod paths;
pub mod server;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::Registry;
use crate::crypto::{signed_message, verify_hex};

// ---------- Límites y constantes ----------

pub const MAX_TITLE_CHARS: usize = 100;
pub const MAX_DESCRIPTION_CHARS: usize = 2000;
pub const MAX_NOTE_CHARS: usize = 1000;
pub const ALLOWED_SEVERITIES: [&str; 4] = ["Baja", "Media", "Alta", "Crítica"];
pub const SYSTEM_ACTOR: &str = "sistema";

// ---------- Comandos ----------

// Lo que va DENTRO del payload firmado. El reporter nunca viaja: es el firmante.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "cmd", rename_all = "UPPERCASE")]
pub enum Command {
    Enviar { title: String, description: String, severity: String },
    Asignar { ticket_id: u64 },
    Resolver { ticket_id: u64, note: String },
    Listar,
    Validar,
    #[serde(rename = "CREAR_USUARIO")]
    CrearUsuario { username: String, role: String },
    #[serde(rename = "LISTAR_USUARIOS")]
    ListarUsuarios,
}

fn validate_field(name: &str, value: &str, max_chars: usize, allow_control: bool) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("El campo '{}' no puede estar vacío", name));
    }
    if value.chars().count() > max_chars {
        return Err(format!("El campo '{}' excede {} caracteres", name, max_chars));
    }
    if !allow_control && value.chars().any(|c| c.is_control()) {
        return Err(format!("El campo '{}' contiene caracteres de control", name));
    }
    Ok(())
}

pub fn validate_command(cmd: &Command) -> Result<(), String> {
    match cmd {
        Command::Enviar { title, description, severity } => {
            validate_field("title", title, MAX_TITLE_CHARS, false)?;
            validate_field("description", description, MAX_DESCRIPTION_CHARS, true)?;
            if !ALLOWED_SEVERITIES.contains(&severity.as_str()) {
                return Err(format!(
                    "Severidad inválida. Valores permitidos: {}",
                    ALLOWED_SEVERITIES.join(", ")
                ));
            }
            Ok(())
        }
        Command::Resolver { note, .. } => validate_field("note", note, MAX_NOTE_CHARS, true),
        Command::CrearUsuario { username, role } => {
            validate_field("username", username, 32, false)?;
            let valid_roles = ["reportante", "analista", "admin"];
            if !valid_roles.contains(&role.as_str()) {
                return Err(format!("Rol inválido. Valores permitidos: {}", valid_roles.join(", ")));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// ---------- Bloques ----------

// La petición firmada tal como llegó. Con esto cualquiera puede re-verificar la autoría.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub ts: u64,
    pub nonce: String,
    pub payload: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub actor: String,
    pub proof: Option<Proof>, // None solo en el bloque génesis
    pub previous_hash: String,
    pub hash: String,
}

impl Block {
    pub fn new(index: u64, actor: &str, proof: Option<Proof>, previous_hash: String) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("El reloj del sistema está antes de 1970")
            .as_secs();

        let hash = Block::calculate_hash(index, timestamp, actor, &proof, &previous_hash);
        Block { index, timestamp, actor: actor.to_string(), proof, previous_hash, hash }
    }

    // El hash cubre TAMBIÉN la prueba de firma: alterarla cambia el hash.
    pub fn calculate_hash(
        index: u64,
        timestamp: u64,
        actor: &str,
        proof: &Option<Proof>,
        previous_hash: &str,
    ) -> String {
        let data = serde_json::to_string(&(index, timestamp, actor, proof, previous_hash))
            .expect("Error al serializar el bloque");

        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn recalculate_hash(&self) -> String {
        Block::calculate_hash(self.index, self.timestamp, &self.actor, &self.proof, &self.previous_hash)
    }
}

// Verifica solo hashes y enlaces (no necesita claves).
pub fn verify_blocks(blocks: &[Block]) -> Result<(), String> {
    for i in 0..blocks.len() {
        let current = &blocks[i];

        if current.index != i as u64 {
            return Err(format!("Bloque {}: índice fuera de secuencia", current.index));
        }
        if current.hash != current.recalculate_hash() {
            return Err(format!("Bloque {}: contenido alterado", current.index));
        }
        if i > 0 {
            let previous = &blocks[i - 1];
            if current.previous_hash != previous.hash {
                return Err(format!(
                    "Bloque {}: enlace roto con el bloque {}",
                    current.index, previous.index
                ));
            }
        }
    }
    Ok(())
}

// ---------- Estado de los tickets (se CALCULA reproduciendo eventos) ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Abierto,
    Asignado,
    Resuelto,
}

#[derive(Debug, Clone, Serialize)]
pub struct TicketState {
    pub id: u64,
    pub title: String,
    pub description: String,
    pub reporter: String,
    pub severity: String,
    pub created_at: u64,
    pub status: Status,
    pub assignee: Option<String>,
    pub resolved_by: Option<String>,
    pub resolution: Option<String>,
}

pub type States = BTreeMap<u64, TicketState>;

// La máquina de estados. La usan el servidor (al admitir) y la verificación (al auditar):
// las mismas reglas en los dos sitios.
pub fn apply(
    states: &mut States,
    index: u64,
    timestamp: u64,
    actor: &str,
    cmd: &Command,
) -> Result<(), String> {
    match cmd {
        Command::Enviar { title, description, severity } => {
            states.insert(
                index,
                TicketState {
                    id: index,
                    title: title.clone(),
                    description: description.clone(),
                    reporter: actor.to_string(),
                    severity: severity.clone(),
                    created_at: timestamp,
                    status: Status::Abierto,
                    assignee: None,
                    resolved_by: None,
                    resolution: None,
                },
            );
            Ok(())
        }
        Command::Asignar { ticket_id } => {
            let t = states
                .get_mut(ticket_id)
                .ok_or_else(|| format!("El ticket {} no existe", ticket_id))?;
            if t.status != Status::Abierto {
                return Err(format!("El ticket {} no está abierto", ticket_id));
            }
            if t.reporter == actor {
                return Err(String::from(
                    "Cuatro ojos: quien reporta un ticket no puede asignárselo",
                ));
            }
            t.status = Status::Asignado;
            t.assignee = Some(actor.to_string());
            Ok(())
        }
        Command::Resolver { ticket_id, note } => {
            let t = states
                .get_mut(ticket_id)
                .ok_or_else(|| format!("El ticket {} no existe", ticket_id))?;
            if t.status != Status::Asignado {
                return Err(format!("El ticket {} no está en estado asignado", ticket_id));
            }
            if t.reporter == actor {
                return Err(String::from(
                    "Cuatro ojos: quien reporta un ticket no puede resolverlo",
                ));
            }
            if t.assignee.as_deref() != Some(actor) {
                return Err(String::from("Solo el analista asignado puede resolver el ticket"));
            }
            t.status = Status::Resuelto;
            t.resolved_by = Some(actor.to_string());
            t.resolution = Some(note.clone());
            Ok(())
        }
        Command::Listar | Command::Validar | Command::CrearUsuario { .. } | Command::ListarUsuarios => {
            Err(String::from("Ese comando no se registra en la cadena"))
        }
    }
}

// A qué ticket se refiere un bloque (para filtrar lo que ve cada reportante).
pub fn ticket_id_of(block: &Block) -> Option<u64> {
    let proof = block.proof.as_ref()?;
    match serde_json::from_str::<Command>(&proof.payload).ok()? {
        Command::Enviar { .. } => Some(block.index),
        Command::Asignar { ticket_id } | Command::Resolver { ticket_id, .. } => Some(ticket_id),
        _ => None,
    }
}

fn replay(blocks: &[Block]) -> Result<States, String> {
    let mut states = States::new();
    for b in blocks.iter().skip(1) {
        let proof = b
            .proof
            .as_ref()
            .ok_or_else(|| format!("Bloque {}: falta la prueba de firma", b.index))?;
        let cmd: Command = serde_json::from_str(&proof.payload)
            .map_err(|e| format!("Bloque {}: comando inválido: {}", b.index, e))?;
        apply(&mut states, b.index, b.timestamp, &b.actor, &cmd)
            .map_err(|e| format!("Bloque {}: {}", b.index, e))?;
    }
    Ok(states)
}

// Auditoría COMPLETA: hashes + enlaces + firma de cada evento + reglas de negocio.
// Necesita solo las claves PÚBLICAS: se puede ejecutar offline, sin confiar en el servidor.
pub fn verify_chain(blocks: &[Block], registry: &Registry) -> Result<States, String> {
    verify_blocks(blocks)?;

    if let Some(g) = blocks.first() {
        if g.proof.is_some() || g.actor != SYSTEM_ACTOR {
            return Err(String::from("Bloque 0: génesis inválido"));
        }
    }

    let mut states = States::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for b in blocks.iter().skip(1) {
        let proof = b
            .proof
            .as_ref()
            .ok_or_else(|| format!("Bloque {}: falta la prueba de firma", b.index))?;
        let user = registry
            .get(&b.actor)
            .ok_or_else(|| format!("Bloque {}: actor desconocido '{}'", b.index, b.actor))?;

        let message = signed_message(&b.actor, proof.ts, &proof.nonce, &proof.payload);
        verify_hex(&user.public_key, &message, &proof.sig)
            .map_err(|_| format!("Bloque {}: la firma de '{}' no es válida", b.index, b.actor))?;

        if !seen.insert((b.actor.clone(), proof.nonce.clone())) {
            return Err(format!("Bloque {}: nonce repetido (replay dentro de la cadena)", b.index));
        }

        let cmd: Command = serde_json::from_str(&proof.payload)
            .map_err(|e| format!("Bloque {}: comando inválido: {}", b.index, e))?;
        apply(&mut states, b.index, b.timestamp, &b.actor, &cmd)
            .map_err(|e| format!("Bloque {}: {}", b.index, e))?;
    }
    Ok(states)
}

// ---------- Cadena ----------

pub struct Blockchain {
    pub blocks: Vec<Block>,
}

impl Blockchain {
    pub fn new() -> Blockchain {
        let genesis = Block::new(0, SYSTEM_ACTOR, None, "0".repeat(64));
        Blockchain { blocks: vec![genesis] }
    }

    pub fn states(&self) -> Result<States, String> {
        replay(&self.blocks)
    }

    // Añade un evento firmado. Las reglas se comprueban ANTES de modificar la cadena.
    pub fn append(&mut self, actor: &str, proof: Proof, cmd: &Command) -> Result<u64, String> {
        let mut states = self.states()?;

        let last = self.blocks.last().expect("La cadena nunca está vacía");
        let index = last.index + 1;
        let previous_hash = last.hash.clone();

        let block = Block::new(index, actor, Some(proof), previous_hash);
        apply(&mut states, index, block.timestamp, actor, cmd)?;

        self.blocks.push(block);
        Ok(index)
    }

    pub fn is_valid(&self, registry: &Registry) -> Result<(), String> {
        verify_chain(&self.blocks, registry).map(|_| ())
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.blocks)
            .map_err(|e| format!("Error al serializar: {}", e))?;

        let tmp = format!("{}.tmp", path);
        fs::write(&tmp, json).map_err(|e| format!("Error al escribir {}: {}", tmp, e))?;
        fs::rename(&tmp, path).map_err(|e| format!("Error al reemplazar {}: {}", path, e))?;
        Ok(())
    }

    pub fn load(path: &str, registry: &Registry) -> Result<Blockchain, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("No se pudo leer {}: {}", path, e))?;

        let blocks: Vec<Block> = serde_json::from_str(&content)
            .map_err(|e| format!("Archivo corrupto o con formato inválido: {}", e))?;

        if blocks.is_empty() {
            return Err(String::from("La cadena guardada está vacía"));
        }

        verify_chain(&blocks, registry)?;
        Ok(Blockchain { blocks })
    }

    pub fn open(path: &str, registry: &Registry) -> Result<Blockchain, String> {
        if Path::new(path).exists() {
            Blockchain::load(path, registry)
        } else {
            let chain = Blockchain::new();
            chain.save(path)?;
            Ok(chain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enviar() -> Command {
        Command::Enviar {
            title: "t".into(),
            description: "d".into(),
            severity: "Alta".into(),
        }
    }

    #[test]
    fn flujo_completo() {
        let mut s = States::new();
        apply(&mut s, 1, 100, "walter", &enviar()).unwrap();
        apply(&mut s, 2, 101, "ana", &Command::Asignar { ticket_id: 1 }).unwrap();
        apply(&mut s, 3, 102, "ana", &Command::Resolver { ticket_id: 1, note: "ok".into() }).unwrap();
        assert_eq!(s[&1].status, Status::Resuelto);
    }

    #[test]
    fn cuatro_ojos_al_asignar() {
        let mut s = States::new();
        apply(&mut s, 1, 100, "ana", &enviar()).unwrap();
        assert!(apply(&mut s, 2, 101, "ana", &Command::Asignar { ticket_id: 1 }).is_err());
    }

    #[test]
    fn solo_el_asignado_resuelve() {
        let mut s = States::new();
        apply(&mut s, 1, 100, "walter", &enviar()).unwrap();
        apply(&mut s, 2, 101, "ana", &Command::Asignar { ticket_id: 1 }).unwrap();
        let r = apply(&mut s, 3, 102, "bruno", &Command::Resolver { ticket_id: 1, note: "x".into() });
        assert!(r.is_err());
    }

    #[test]
    fn no_se_resuelve_sin_asignar() {
        let mut s = States::new();
        apply(&mut s, 1, 100, "walter", &enviar()).unwrap();
        let r = apply(&mut s, 2, 101, "ana", &Command::Resolver { ticket_id: 1, note: "x".into() });
        assert!(r.is_err());
    }

    #[test]
    fn ticket_inexistente() {
        let mut s = States::new();
        assert!(apply(&mut s, 1, 100, "ana", &Command::Asignar { ticket_id: 99 }).is_err());
    }
}