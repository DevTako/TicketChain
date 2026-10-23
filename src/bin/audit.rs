use std::fs;

use ticket_chain::auth::Registry;
use ticket_chain::paths;
use ticket_chain::{verify_chain, Block, Command};

fn fail(msg: &str) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

fn format_utc(ts: u64) -> String {
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

fn describe(cmd: &Command) -> String {
    match cmd {
        Command::Enviar { title, severity, .. } => format!("ENVIAR   \"{}\" [{}]", title, severity),
        Command::Asignar { ticket_id } => format!("ASIGNAR  ticket {}", ticket_id),
        Command::Resolver { ticket_id, note } => format!("RESOLVER ticket {}: {}", ticket_id, note),
        _ => String::from("(comando no registrable)"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut chain_path = paths::data_path("chain.json");
    let mut users_path = paths::data_path("users.json");
    let mut anchor: Option<String> = None;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next();
        match (flag.as_str(), value) {
            ("--chain", Some(v)) => chain_path = v.clone(),
            ("--users", Some(v)) => users_path = v.clone(),
            ("--anchor", Some(v)) => anchor = Some(v.trim().to_lowercase()),
            _ => fail("Uso: audit [--chain archivo] [--users archivo] [--anchor hash]"),
        }
    }

    let content = match fs::read_to_string(&chain_path) {
        Ok(c) => c,
        Err(e) => fail(&format!("No se pudo leer {}: {}", chain_path, e)),
    };
    let blocks: Vec<Block> = match serde_json::from_str(&content) {
        Ok(b) => b,
        Err(e) => fail(&format!("{} con formato inválido: {}", chain_path, e)),
    };
    if blocks.is_empty() {
        fail("La cadena está vacía.");
    }
    let registry = match Registry::load(&users_path) {
        Ok(r) => r,
        Err(e) => fail(&e),
    };

    println!("Auditando {} ({} bloques) con {} claves públicas\n", chain_path, blocks.len(), registry.len());

    let states = match verify_chain(&blocks, &registry) {
        Ok(s) => s,
        Err(e) => {
            println!("AUDITORÍA FALLIDA: {}", e);
            std::process::exit(1);
        }
    };
    println!("Hashes, enlaces, firmas Ed25519 y reglas de negocio: VERIFICADOS\n");

    println!("--- Historial (cada evento fue firmado por su autor) ---");
    for b in blocks.iter().skip(1) {
        let text = match b.proof.as_ref().and_then(|p| serde_json::from_str::<Command>(&p.payload).ok()) {
            Some(cmd) => describe(&cmd),
            None => String::from("(ilegible)"),
        };
        println!("#{:<3} {}  {:<8} {}", b.index, format_utc(b.timestamp), b.actor, text);
    }

    println!("\n--- Estado actual de los tickets ---");
    for t in states.values() {
        println!(
            "Ticket {:<3} {:<10?} \"{}\"  reportó: {}  asignado: {}",
            t.id,
            t.status,
            t.title,
            t.reporter,
            t.assignee.as_deref().unwrap_or("-")
        );
    }

    let last = blocks.len() - 1;
    println!("\nHash de cabeza (guárdelo FUERA del servidor como ancla):");
    println!("{}", blocks[last].hash);

    if let Some(a) = anchor {
        println!();
        match blocks.iter().position(|b| b.hash == a) {
            Some(i) if i == last => println!("ANCLA: coincide con la cabeza actual."),
            Some(i) => println!(
                "ANCLA: encontrada en el bloque {}; la cadena creció {} bloques desde entonces (normal).",
                i,
                last - i
            ),
            None => {
                println!("ALERTA: el ancla NO está en la cadena. Fue truncada o reescrita.");
                std::process::exit(2);
            }
        }
    }
}
