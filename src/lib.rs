pub mod auth;
pub mod crypto;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------- Límites de validación (compartidos con la GUI) ----------

pub const MAX_TITLE_CHARS: usize = 100;
pub const MAX_DESCRIPTION_CHARS: usize = 2000;
pub const MAX_REPORTER_CHARS: usize = 50;
pub const ALLOWED_SEVERITIES: [&str; 4] = ["Baja", "Media", "Alta", "Crítica"];

// ---------- Modelo de datos ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub id: u32,
    pub title: String,
    pub description: String,
    pub reporter: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub ticket: Ticket,
    pub previous_hash: String,
    pub hash: String,
}

impl Block {
    pub fn new(index: u64, ticket: Ticket, previous_hash: String) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("El reloj del sistema está antes de 1970")
            .as_secs();

        let hash = Block::calculate_hash(index, timestamp, &ticket, &previous_hash);
        Block { index, timestamp, ticket, previous_hash, hash }
    }

    pub fn calculate_hash(
        index: u64,
        timestamp: u64,
        ticket: &Ticket,
        previous_hash: &str,
    ) -> String {
        let data = serde_json::to_string(&(index, timestamp, ticket, previous_hash))
            .expect("Error al serializar el bloque");

        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn recalculate_hash(&self) -> String {
        Block::calculate_hash(self.index, self.timestamp, &self.ticket, &self.previous_hash)
    }
}

// Verifica una lista de bloques. Es una función libre sobre un slice (&[Block])
// para que la GUI pueda verificar los bloques que recibe del servidor
// sin necesitar una Blockchain completa.
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

pub struct Blockchain {
    pub blocks: Vec<Block>,
}

impl Blockchain {
    pub fn new() -> Blockchain {
        let genesis_ticket = Ticket {
            id: 0,
            title: String::from("Bloque génesis"),
            description: String::from("Inicio de la cadena de custodia"),
            reporter: String::from("sistema"),
            severity: String::from("Info"),
        };
        let genesis = Block::new(0, genesis_ticket, "0".repeat(64));
        Blockchain { blocks: vec![genesis] }
    }

    pub fn add_ticket(&mut self, mut ticket: Ticket) -> u64 {
        let last = self.blocks.last().expect("La cadena nunca está vacía");
        let previous_hash = last.hash.clone();
        let index = last.index + 1;

        ticket.id = index as u32;
        self.blocks.push(Block::new(index, ticket, previous_hash));
        index
    }

    pub fn is_valid(&self) -> Result<(), String> {
        verify_blocks(&self.blocks)
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.blocks)
            .map_err(|e| format!("Error al serializar: {}", e))?;

        let tmp = format!("{}.tmp", path);
        fs::write(&tmp, json).map_err(|e| format!("Error al escribir {}: {}", tmp, e))?;
        fs::rename(&tmp, path).map_err(|e| format!("Error al reemplazar {}: {}", path, e))?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Blockchain, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("No se pudo leer {}: {}", path, e))?;

        let blocks: Vec<Block> = serde_json::from_str(&content)
            .map_err(|e| format!("Archivo corrupto o con formato inválido: {}", e))?;

        if blocks.is_empty() {
            return Err(String::from("La cadena guardada está vacía"));
        }

        let chain = Blockchain { blocks };
        chain.is_valid()?;
        Ok(chain)
    }

    pub fn open(path: &str) -> Result<Blockchain, String> {
        if Path::new(path).exists() {
            Blockchain::load(path)
        } else {
            let chain = Blockchain::new();
            chain.save(path)?;
            Ok(chain)
        }
    }
}

// ---------- Validación de entrada ----------

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

pub fn validate_ticket(title: &str, description: &str, reporter: &str, severity: &str) -> Result<(), String> {
    validate_field("title", title, MAX_TITLE_CHARS, false)?;
    validate_field("description", description, MAX_DESCRIPTION_CHARS, true)?;
    validate_field("reporter", reporter, MAX_REPORTER_CHARS, false)?;

    if !ALLOWED_SEVERITIES.contains(&severity) {
        return Err(format!(
            "Severidad inválida. Valores permitidos: {}",
            ALLOWED_SEVERITIES.join(", ")
        ));
    }
    Ok(())
}