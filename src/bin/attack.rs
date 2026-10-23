use std::fs;

use ticket_chain::auth::Registry;
use ticket_chain::paths;
use ticket_chain::{verify_blocks, verify_chain, Block};

fn usage() -> ! {
    eprintln!("Uso (attack <modo> ...):");
    eprintln!("  downgrade <bloque>            rebaja Alta -> Baja en un evento y repara los hashes");
    eprintln!("  forge-actor <bloque> <user>   cambia el autor de un evento y repara los hashes");
    eprintln!("  truncate <n>                  elimina los últimos n bloques");
    eprintln!("Lee chain.json y escribe chain_tampered.json (no modifica el original).");
    std::process::exit(2);
}

fn fail(msg: &str) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

fn parse_usize(s: &str) -> usize {
    match s.parse() {
        Ok(n) => n,
        Err(_) => fail("Se esperaba un número."),
    }
}

// Lo que haría un atacante competente: recalcular hash y enlace desde `start` hasta el final,
// para que la cadena parezca coherente.
fn rehash_from(blocks: &mut [Block], start: usize) {
    for i in start..blocks.len() {
        if i > 0 {
            let previous = blocks[i - 1].hash.clone();
            blocks[i].previous_hash = previous;
        }
        blocks[i].hash = blocks[i].recalculate_hash();
    }
}

fn verdict<T>(r: Result<T, String>) -> String {
    match r {
        Ok(_) => String::from("APROBADA"),
        Err(e) => format!("RECHAZADA -> {}", e),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }

    let chain_path = paths::data_path("chain.json");
    let users_path = paths::data_path("users.json");
    let tampered_path = paths::data_path("chain_tampered.json");

    let content = match fs::read_to_string(&chain_path) {
        Ok(c) => c,
        Err(e) => fail(&format!("No se pudo leer {}: {}", chain_path, e)),
    };
    let mut blocks: Vec<Block> = match serde_json::from_str(&content) {
        Ok(b) => b,
        Err(e) => fail(&format!("{} inválido: {}", chain_path, e)),
    };
    let registry = match Registry::load(&users_path) {
        Ok(r) => r,
        Err(e) => fail(&e),
    };

    let description = match args[0].as_str() {
        "downgrade" => {
            if args.len() != 2 {
                usage();
            }
            let idx = parse_usize(&args[1]);
            if idx == 0 || idx >= blocks.len() {
                fail("Índice de bloque fuera de rango (use 1 hasta el último).");
            }
            {
                let proof = match blocks[idx].proof.as_mut() {
                    Some(p) => p,
                    None => fail("Ese bloque no tiene prueba de firma."),
                };
                if !proof.payload.contains("\"Alta\"") {
                    fail("Ese bloque no contiene la severidad \"Alta\"; pruebe con otro.");
                }
                proof.payload = proof.payload.replace("\"Alta\"", "\"Baja\"");
            }
            rehash_from(&mut blocks, idx);
            format!("Bloque {}: severidad Alta -> Baja, hashes recalculados hasta el final", idx)
        }
        "forge-actor" => {
            if args.len() != 3 {
                usage();
            }
            let idx = parse_usize(&args[1]);
            if idx == 0 || idx >= blocks.len() {
                fail("Índice de bloque fuera de rango (use 1 hasta el último).");
            }
            blocks[idx].actor = args[2].clone();
            rehash_from(&mut blocks, idx);
            format!("Bloque {}: autor cambiado a '{}', hashes recalculados hasta el final", idx, args[2])
        }
        "truncate" => {
            if args.len() != 2 {
                usage();
            }
            let n = parse_usize(&args[1]);
            if n == 0 || n >= blocks.len() {
                fail("Cantidad fuera de rango (debe quedar al menos el génesis).");
            }
            let new_len = blocks.len() - n;
            blocks.truncate(new_len);
            format!("Se eliminaron los últimos {} bloques", n)
        }
        _ => usage(),
    };

    println!("Ataque aplicado: {}", description);
    println!("Auditoría de hashes y enlaces (la de la versión 1): {}", verdict(verify_blocks(&blocks)));
    println!("Auditoría completa con firmas Ed25519             : {}", verdict(verify_chain(&blocks, &registry)));

    let json = match serde_json::to_string_pretty(&blocks) {
        Ok(j) => j,
        Err(e) => fail(&format!("Error al serializar: {}", e)),
    };
    if let Err(e) = fs::write(&tampered_path, json) {
        fail(&format!("No se pudo escribir {}: {}", tampered_path, e));
    }
    println!("\nCadena alterada guardada en {} ({} no se modificó).", tampered_path, chain_path);
}
