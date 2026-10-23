use std::path::PathBuf;

/// Directorio donde reside el ejecutable.
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .expect("No se pudo determinar la ruta del ejecutable")
        .parent()
        .expect("El ejecutable no tiene directorio padre")
        .to_path_buf()
}

/// Directorio raíz de datos. Prioridad:
/// 1. Variable de entorno `TC_DATA`
/// 2. Directorio del ejecutable (si contiene `users.json` o por defecto en distribución)
/// 3. Directorio de trabajo actual (desarrollo con `cargo run`)
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TC_DATA") {
        return PathBuf::from(dir);
    }
    let exe = exe_dir();
    if exe.join("users.json").exists() {
        return exe;
    }
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("users.json").exists() {
            return cwd;
        }
    }
    exe
}

/// Ruta a un archivo de datos (relativa a `data_dir()`).
pub fn data_path(filename: &str) -> String {
    data_dir().join(filename).to_string_lossy().to_string()
}

/// Directorio de claves privadas.
pub fn keys_dir() -> String {
    data_dir().join("keys").to_string_lossy().to_string()
}

/// Ruta a la clave privada de un usuario.
pub fn key_path(user: &str) -> String {
    data_dir()
        .join("keys")
        .join(format!("{}.key", user))
        .to_string_lossy()
        .to_string()
}

/// Dirección de escucha del servidor (configurable con `TC_BIND`).
pub fn server_bind() -> String {
    std::env::var("TC_BIND").unwrap_or_else(|_| String::from("127.0.0.1:7878"))
}

/// Dirección del servidor para clientes (configurable con `TC_SERVER`).
pub fn server_addr() -> String {
    std::env::var("TC_SERVER").unwrap_or_else(|_| String::from("127.0.0.1:7878"))
}

/// Inicializa archivos por defecto (usuarios y claves básicas) si no existen.
pub fn ensure_environment() {
    let _ = std::fs::create_dir_all(keys_dir());
    let users_file = data_path("users.json");
    if !std::path::Path::new(&users_file).exists() {
        let default_users = r#"[
  {
    "user": "admin",
    "role": "admin",
    "public_key": "5d4ae91d608d092e700e5dd099d022223e20d80db909021eb603704c26cc8016"
  },
  {
    "user": "ana",
    "role": "analista",
    "public_key": "d74bdc792c51d4f9a72a713711b4d89bde175fe7b17543ee762abf111acee566"
  },
  {
    "user": "walter",
    "role": "reportante",
    "public_key": "8fc7db1244f5b83cf51dd37b4b885da5c8f696324803feff9523aa091ca9eed1"
  }
]"#;
        let _ = std::fs::write(&users_file, default_users);
    }

    let default_keys = [
        ("admin", "244417b9e0d0d9f53d4a4f47e30722e45d39563a6cef09e6a067fa37543cb978"),
        ("ana", "2f89116601b3ec1d37463636a1c5ba1362a5c71fb20a382dc78fcf0b1e1af77c"),
        ("walter", "9d6d2f4661f7ecb71c3cc516566d60a2e85c430bbf4fa45b2edfce3f0c64d4ee"),
    ];

    for (user, privkey) in default_keys {
        let p = key_path(user);
        if !std::path::Path::new(&p).exists() {
            let _ = std::fs::write(&p, privkey);
        }
    }
}
