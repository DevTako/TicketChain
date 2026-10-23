use eframe::egui;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use ticket_chain::{validate_ticket, verify_blocks, Block, ALLOWED_SEVERITIES};

const SERVER_ADDR: &str = "127.0.0.1:7878";
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

// ---------- Red ----------

// Envía UNA línea de JSON y devuelve UNA línea de respuesta.
fn send_command(cmd: &str) -> Result<String, String> {
    let addr: SocketAddr = SERVER_ADDR
        .parse()
        .map_err(|e| format!("Dirección inválida: {}", e))?;

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("No se pudo conectar al servidor: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    writer
        .write_all(cmd.as_bytes())
        .and_then(|_| writer.write_all(b"\n"))
        .map_err(|e| format!("Error al enviar: {}", e))?;

    let mut reader = BufReader::new(stream).take(MAX_RESPONSE_BYTES);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("Error al leer la respuesta: {}", e))?;
    Ok(line)
}

#[derive(Deserialize)]
struct ListResponse {
    status: String,
    blocks: Option<Vec<Block>>,
    message: Option<String>,
}

fn fetch_chain() -> Result<Vec<Block>, String> {
    let line = send_command(r#"{"cmd":"LISTAR"}"#)?;
    let resp: ListResponse =
        serde_json::from_str(&line).map_err(|e| format!("Respuesta inválida: {}", e))?;

    if resp.status != "ok" {
        return Err(resp.message.unwrap_or_else(|| String::from("Error desconocido")));
    }
    resp.blocks
        .ok_or_else(|| String::from("La respuesta no incluye bloques"))
}

fn submit_ticket(title: &str, description: &str, reporter: &str, severity: &str) -> Result<u64, String> {
    // json! se encarga de escapar comillas y saltos de línea correctamente.
    let cmd = serde_json::json!({
        "cmd": "ENVIAR",
        "title": title,
        "description": description,
        "reporter": reporter,
        "severity": severity,
    })
    .to_string();

    let line = send_command(&cmd)?;
    let v: serde_json::Value =
        serde_json::from_str(&line).map_err(|e| format!("Respuesta inválida: {}", e))?;

    if v["status"].as_str() == Some("ok") {
        Ok(v["ticket_id"].as_u64().unwrap_or(0))
    } else {
        Err(v["message"].as_str().unwrap_or("Error desconocido").to_string())
    }
}

// ---------- Utilidades ----------

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

// ---------- Aplicación ----------

struct GuiApp {
    blocks: Vec<Block>,
    status: String,
    is_error: bool,
    // Resultado de la verificación LOCAL (recalculada en este equipo).
    verification: Result<(), String>,
    // Campos del formulario.
    title: String,
    description: String,
    reporter: String,
    severity: String,
}

impl GuiApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = GuiApp {
            blocks: Vec::new(),
            status: String::from("Sin conectar"),
            is_error: false,
            verification: Ok(()),
            title: String::new(),
            description: String::new(),
            reporter: String::new(),
            severity: ALLOWED_SEVERITIES[1].to_string(),
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        match fetch_chain() {
            Ok(blocks) => {
                // El verificador NO le pregunta al servidor: recalcula los hashes aquí.
                self.verification = verify_blocks(&blocks);
                self.status = format!("Conectado: {} bloques recibidos", blocks.len());
                self.is_error = false;
                self.blocks = blocks;
            }
            Err(e) => {
                self.status = e;
                self.is_error = true;
            }
        }
    }

    fn submit(&mut self) {
        // Validación en el cliente: comodidad, no seguridad (el servidor revalida).
        if let Err(e) = validate_ticket(&self.title, &self.description, &self.reporter, &self.severity) {
            self.status = e;
            self.is_error = true;
            return;
        }

        match submit_ticket(&self.title, &self.description, &self.reporter, &self.severity) {
            Ok(id) => {
                self.title.clear();
                self.description.clear();
                self.refresh();
                self.status = format!("Ticket #{} registrado en la cadena", id);
                self.is_error = false;
            }
            Err(e) => {
                self.status = e;
                self.is_error = true;
            }
        }
    }

    // Altera la copia LOCAL del bloque 1. El servidor no se toca.
    fn simulate_tampering(&mut self) {
        if self.blocks.len() > 1 {
            self.blocks[1].ticket.title.push_str(" (alterado)");
            self.verification = verify_blocks(&self.blocks);
            self.status = String::from("Bloque 1 alterado en la copia local; el servidor no fue modificado");
            self.is_error = false;
        }
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Ticket Chain - Cadena de custodia");
            ui.separator();

            // ----- Formulario -----
            ui.label(egui::RichText::new("Nuevo ticket").strong());
            egui::Grid::new("formulario").num_columns(2).show(ui, |ui| {
                ui.label("Título:");
                ui.text_edit_singleline(&mut self.title);
                ui.end_row();

                ui.label("Reporter:");
                ui.text_edit_singleline(&mut self.reporter);
                ui.end_row();

                ui.label("Severidad:");
                egui::ComboBox::from_id_salt("severidad")
                    .selected_text(self.severity.clone())
                    .show_ui(ui, |ui| {
                        for s in ALLOWED_SEVERITIES {
                            ui.selectable_value(&mut self.severity, s.to_string(), s);
                        }
                    });
                ui.end_row();

                ui.label("Descripción:");
                ui.text_edit_multiline(&mut self.description);
                ui.end_row();
            });

            ui.horizontal(|ui| {
                if ui.button("Enviar ticket").clicked() {
                    self.submit();
                }
                if ui.button("Actualizar").clicked() {
                    self.refresh();
                }
                if ui.button("Simular manipulación (solo local)").clicked() {
                    self.simulate_tampering();
                }
            });

            // ----- Estado -----
            let color = if self.is_error { egui::Color32::RED } else { egui::Color32::GREEN };
            ui.colored_label(color, &self.status);

            match &self.verification {
                Ok(()) => ui.colored_label(
                    egui::Color32::GREEN,
                    "Verificación local: cadena íntegra (SHA-256 recalculado en este equipo)",
                ),
                Err(e) => ui.colored_label(
                    egui::Color32::RED,
                    format!("INTEGRIDAD COMPROMETIDA: {}", e),
                ),
            };

            ui.separator();

            // ----- Tabla -----
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("tabla_bloques")
                    .striped(true)
                    .num_columns(6)
                    .show(ui, |ui| {
                        for titulo in ["#", "Fecha", "Título", "Severidad", "Reporter", "Hash"] {
                            ui.label(egui::RichText::new(titulo).strong());
                        }
                        ui.end_row();

                        for b in &self.blocks {
                            ui.label(b.index.to_string());
                            ui.label(format_utc(b.timestamp));
                            ui.label(&b.ticket.title);
                            ui.label(&b.ticket.severity);
                            ui.label(&b.ticket.reporter);
                            ui.monospace(format!("{}...", &b.hash[..12]));
                            ui.end_row();
                        }
                    });
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "Ticket Chain - Cliente",
        eframe::NativeOptions::default(),
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
}