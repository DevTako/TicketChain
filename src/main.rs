use ticket_chain::paths;
use ticket_chain::server::start_server_listener;

fn main() {
    let chain_file = paths::data_path("chain.json");
    let users_file = paths::data_path("users.json");
    let bind_addr = paths::server_bind();

    println!("Datos en: {}", paths::data_path(""));

    if let Err(e) = start_server_listener(&bind_addr, &chain_file, &users_file) {
        eprintln!("ERROR CRÍTICO: {}", e);
        std::process::exit(1);
    }
}
