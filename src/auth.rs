use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::validate_public_key_hex;

// Una petición solo es válida si su marca de tiempo está a ±60 s de nuestro reloj.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn timestamp_in_window(ts: u64, now: u64) -> bool {
    ts.abs_diff(now) <= MAX_CLOCK_SKEW_SECS
}

// Listas blancas estrictas: estos textos entran en rutas de archivo y en el mensaje firmado.
pub fn is_valid_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn is_valid_nonce(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------- Roles y permisos ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Reportante,
    Analista,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Enviar,
    ListarTodo,
    Validar,
}

// La matriz de permisos. Un solo lugar, fácil de auditar.
pub fn can(role: Role, action: Action) -> bool {
    match (role, action) {
        (_, Action::Enviar) => true,
        (Role::Analista | Role::Admin, Action::ListarTodo) => true,
        (Role::Analista | Role::Admin, Action::Validar) => true,
        _ => false,
    }
}

// ---------- Registro de usuarios ----------

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub user: String,
    pub role: Role,
    pub public_key: String,
}

pub struct Registry {
    users: HashMap<String, User>,
}

impl Registry {
    pub fn load(path: &str) -> Result<Registry, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("No se pudo leer {}: {}", path, e))?;
        let list: Vec<User> = serde_json::from_str(&content)
            .map_err(|e| format!("{} con formato inválido: {}", path, e))?;

        if list.is_empty() {
            return Err(format!("{} no contiene usuarios", path));
        }

        let mut users: HashMap<String, User> = HashMap::new();
        for u in list {
            if !is_valid_username(&u.user) {
                return Err(format!("Nombre de usuario inválido: '{}'", u.user));
            }
            validate_public_key_hex(&u.public_key)
                .map_err(|e| format!("Usuario '{}': {}", u.user, e))?;
            if users.contains_key(&u.user) {
                return Err(format!("Usuario duplicado: '{}'", u.user));
            }
            // Dos usuarios con la misma clave pública serían indistinguibles.
            if users.values().any(|x| x.public_key.eq_ignore_ascii_case(&u.public_key)) {
                return Err(format!("Clave pública repetida (usuario '{}')", u.user));
            }
            users.insert(u.user.clone(), u);
        }
        Ok(Registry { users })
    }

    pub fn get(&self, user: &str) -> Option<&User> {
        self.users.get(user)
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }
}

// ---------- Protección anti-replay ----------

// Recuerda los nonces vistos mientras su petición aún podría ser aceptada por la ventana de tiempo.
pub struct NonceCache {
    seen: HashMap<(String, String), u64>, // (usuario, nonce) -> ts de la petición
}

impl NonceCache {
    pub fn new() -> NonceCache {
        NonceCache { seen: HashMap::new() }
    }

    // Devuelve true si el nonce es nuevo (y lo registra); false si es un replay.
    pub fn check_and_insert(&mut self, user: &str, nonce: &str, ts: u64, now: u64) -> bool {
        // Olvidar lo que ya no puede volver a pasar la ventana de tiempo.
        self.seen.retain(|_, t| *t + MAX_CLOCK_SKEW_SECS >= now);

        let key = (user.to_string(), nonce.to_string());
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, ts);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ventana_de_tiempo() {
        assert!(timestamp_in_window(1000, 1000));
        assert!(timestamp_in_window(1000, 1060));
        assert!(timestamp_in_window(1060, 1000));
        assert!(!timestamp_in_window(1000, 1061));
        assert!(!timestamp_in_window(1061, 1000));
    }

    #[test]
    fn nonce_repetido_se_rechaza() {
        let mut cache = NonceCache::new();
        assert!(cache.check_and_insert("ana", "aaaa", 1000, 1000));
        assert!(!cache.check_and_insert("ana", "aaaa", 1000, 1001));
    }

    #[test]
    fn nonce_distinto_o_de_otro_usuario_pasa() {
        let mut cache = NonceCache::new();
        assert!(cache.check_and_insert("ana", "aaaa", 1000, 1000));
        assert!(cache.check_and_insert("ana", "bbbb", 1000, 1000));
        assert!(cache.check_and_insert("walter", "aaaa", 1000, 1000));
    }

    #[test]
    fn matriz_de_permisos() {
        assert!(can(Role::Reportante, Action::Enviar));
        assert!(!can(Role::Reportante, Action::ListarTodo));
        assert!(!can(Role::Reportante, Action::Validar));
        assert!(can(Role::Analista, Action::ListarTodo));
        assert!(can(Role::Analista, Action::Validar));
        assert!(can(Role::Admin, Action::Validar));
    }

    #[test]
    fn validadores_de_formato() {
        assert!(is_valid_username("ana_01"));
        assert!(!is_valid_username("..\\evil"));
        assert!(!is_valid_username("a|b"));
        assert!(is_valid_nonce("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_nonce("corto"));
    }
}