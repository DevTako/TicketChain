use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fs::{self, OpenOptions};
use std::io::Write;

// Genera una clave privada con 32 bytes del generador aleatorio del sistema operativo.
pub fn generate_signing_key() -> Result<SigningKey, String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| format!("No se pudo obtener aleatoriedad del SO: {}", e))?;
    Ok(SigningKey::from_bytes(&seed))
}

// Decodifica hex a un arreglo de exactamente N bytes.
fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("Hex inválido: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| format!("Longitud inválida: se esperaban {} bytes", N))
}

pub fn public_key_hex(sk: &SigningKey) -> String {
    hex::encode(sk.verifying_key().to_bytes())
}

// Firma un mensaje; devuelve la firma (64 bytes) en hex.
pub fn sign_hex(sk: &SigningKey, message: &[u8]) -> String {
    let signature: Signature = sk.sign(message);
    hex::encode(signature.to_bytes())
}

// Verifica una firma con la clave pública (hex). Usa verify_strict, que además
// rechaza firmas maleables y claves públicas de orden pequeño.
pub fn verify_hex(public_key_hex: &str, message: &[u8], signature_hex: &str) -> Result<(), String> {
    let pk_bytes: [u8; 32] = decode_hex(public_key_hex)?;
    let sig_bytes: [u8; 64] = decode_hex(signature_hex)?;

    let public_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| String::from("Clave pública inválida"))?;
    let signature = Signature::from_bytes(&sig_bytes);

    public_key
        .verify_strict(message, &signature)
        .map_err(|_| String::from("Firma inválida"))
}

// Guarda la clave privada. create_new(true) FALLA si el archivo ya existe:
// una clave de identidad no debe sobrescribirse por accidente.
pub fn save_signing_key(path: &str, sk: &SigningKey) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("No se pudo crear {} (¿ya existe?): {}", path, e))?;
    file.write_all(hex::encode(sk.to_bytes()).as_bytes())
        .map_err(|e| format!("Error al escribir {}: {}", path, e))
}

pub fn load_signing_key(path: &str) -> Result<SigningKey, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("No se pudo leer {}: {}", path, e))?;
    let seed: [u8; 32] = decode_hex(&content)?;
    Ok(SigningKey::from_bytes(&seed))
}

// ---------- Añadido en el Paso 7.2 ----------

// Los bytes EXACTOS que se firman. Los campos previos al payload están restringidos
// (usuario y nonce por lista blanca, ts numérico), así que no hay ambigüedad.
pub fn signed_message(user: &str, ts: u64, nonce: &str, payload: &str) -> Vec<u8> {
    format!("TC1|{}|{}|{}|{}", user, ts, nonce, payload).into_bytes()
}

// 16 bytes aleatorios del SO, en hex (32 caracteres).
pub fn random_nonce_hex() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| format!("No se pudo obtener aleatoriedad del SO: {}", e))?;
    Ok(hex::encode(bytes))
}

// Comprueba que un texto hex sea una clave pública Ed25519 válida.
pub fn validate_public_key_hex(public_key_hex: &str) -> Result<(), String> {
    let bytes: [u8; 32] = decode_hex(public_key_hex)?;
    VerifyingKey::from_bytes(&bytes)
        .map(|_| ())
        .map_err(|_| String::from("Clave pública inválida"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firma_valida_se_verifica() {
        let sk = generate_signing_key().unwrap();
        let pk = public_key_hex(&sk);
        let sig = sign_hex(&sk, b"resolver ticket 4");
        assert!(verify_hex(&pk, b"resolver ticket 4", &sig).is_ok());
    }

    #[test]
    fn mensaje_alterado_falla() {
        let sk = generate_signing_key().unwrap();
        let pk = public_key_hex(&sk);
        let sig = sign_hex(&sk, b"resolver ticket 4");
        assert!(verify_hex(&pk, b"resolver ticket 5", &sig).is_err());
    }

    #[test]
    fn clave_ajena_falla() {
        let ana = generate_signing_key().unwrap();
        let intruso = generate_signing_key().unwrap();
        let sig = sign_hex(&intruso, b"resolver ticket 4");
        assert!(verify_hex(&public_key_hex(&ana), b"resolver ticket 4", &sig).is_err());
    }

    #[test]
    fn basura_es_rechazada_sin_panico() {
        let sk = generate_signing_key().unwrap();
        let pk = public_key_hex(&sk);
        assert!(verify_hex(&pk, b"x", "abcd").is_err());
        assert!(verify_hex("no es hex", b"x", "00").is_err());
    }
}