#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use serde::Deserialize;

use ticket_chain::client::{format_utc, Session};
use ticket_chain::{validate_command, Command, ALLOWED_SEVERITIES};

// Solo los campos que el portal muestra; serde ignora el resto.
#[derive(Deserialize)]
struct TicketView {
    id: u64,
    title: String,
    severity: String,
    created_at: u64,
    status: String,
    reporter: String,
    assignee: Option<String>,
    resolution: Option<String>,
}

#[derive(Deserialize)]
struct ListReply {
    role: Option<String>,
    tickets: Vec<TicketView>,
}

#[derive(Deserialize, Clone)]
struct UserView {
    user: String,
    role: String,
    public_key: String,
}

#[derive(Deserialize)]
struct UsersReply {
    users: Vec<UserView>,
}

// ---------- Estado de la aplicación ----------

#[derive(PartialEq)]
enum Tab {
    Tickets,
    Admin,
}

struct PortalApp {
    // Login
    login_user: String,
    session: Option<Session>,
    role: String,

    // Tickets
    tickets: Vec<TicketView>,
    title: String,
    description: String,
    severity: String,

    // Admin — Gestión de usuarios
    tab: Tab,
    users: Vec<UserView>,
    new_username: String,
    new_role: String,
    created_info: Option<CreatedUserInfo>,

    // Estado
    message: String,
    is_error: bool,
}

struct CreatedUserInfo {
    username: String,
    role: String,
    public_key: String,
    private_key: String,
    key_file: String,
}

impl PortalApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        PortalApp {
            login_user: String::new(),
            session: None,
            role: String::new(),
            tickets: Vec::new(),
            title: String::new(),
            description: String::new(),
            severity: ALLOWED_SEVERITIES[1].to_string(),
            tab: Tab::Tickets,
            users: Vec::new(),
            new_username: String::new(),
            new_role: String::from("reportante"),
            created_info: None,
            message: String::from("Identifíquese para continuar"),
            is_error: false,
        }
    }

    fn note(&mut self, msg: String, is_error: bool) {
        self.message = msg;
        self.is_error = is_error;
    }

    fn is_admin(&self) -> bool {
        self.role == "admin"
    }

    // Pide al servidor los tickets que ESTA identidad puede ver.
    fn fetch(&mut self) -> Result<(), String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| String::from("Sin sesión"))?;
        let reply = session.listar()?;
        let parsed: ListReply = serde_json::from_value(reply)
            .map_err(|e| format!("Respuesta inesperada: {}", e))?;
        self.role = parsed.role.unwrap_or_default();
        self.tickets = parsed.tickets;
        Ok(())
    }

    fn fetch_users(&mut self) -> Result<(), String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| String::from("Sin sesión"))?;
        let reply = session.listar_usuarios()?;
        let parsed: UsersReply = serde_json::from_value(reply)
            .map_err(|e| format!("Respuesta inesperada: {}", e))?;
        self.users = parsed.users;
        Ok(())
    }

    fn login(&mut self) {
        match Session::open(self.login_user.trim()) {
            Ok(session) => {
                self.session = Some(session);
                match self.fetch() {
                    Ok(()) => {
                        let n = self.tickets.len();
                        let role_label = match self.role.as_str() {
                            "admin" => "Administrador",
                            "analista" => "Analista",
                            _ => "Reportante",
                        };
                        self.note(
                            format!("Sesión iniciada como {} — {} tickets visibles", role_label, n),
                            false,
                        );
                        // Si es admin, cargar usuarios también.
                        if self.is_admin() {
                            let _ = self.fetch_users();
                        }
                    }
                    Err(e) => {
                        self.session = None;
                        self.note(e, true);
                    }
                }
            }
            Err(e) => self.note(e, true),
        }
    }

    fn submit(&mut self) {
        // Validación local: comodidad para el usuario; el servidor vuelve a validar.
        let cmd = Command::Enviar {
            title: self.title.clone(),
            description: self.description.clone(),
            severity: self.severity.clone(),
        };
        if let Err(e) = validate_command(&cmd) {
            self.note(e, true);
            return;
        }

        let result = match &self.session {
            Some(s) => s.enviar(&self.title, &self.description, &self.severity),
            None => return,
        };

        match result {
            Ok(reply) => {
                let id = reply["ticket_id"].as_u64().unwrap_or(0);
                self.title.clear();
                self.description.clear();
                match self.fetch() {
                    Ok(()) => self.note(format!("Ticket #{} enviado", id), false),
                    Err(e) => self.note(
                        format!("Ticket #{} enviado, pero no se pudo actualizar: {}", id, e),
                        true,
                    ),
                }
            }
            Err(e) => self.note(e, true),
        }
    }

    fn create_user(&mut self) {
        let username = self.new_username.trim().to_string();
        let role = self.new_role.clone();

        if username.is_empty() {
            self.note(String::from("El nombre de usuario no puede estar vacío"), true);
            return;
        }

        let result = match &self.session {
            Some(s) => s.crear_usuario(&username, &role),
            None => return,
        };

        match result {
            Ok(reply) => {
                self.created_info = Some(CreatedUserInfo {
                    username: reply["username"].as_str().unwrap_or("").to_string(),
                    role: reply["role"].as_str().unwrap_or("").to_string(),
                    public_key: reply["public_key"].as_str().unwrap_or("").to_string(),
                    private_key: reply["private_key"].as_str().unwrap_or("").to_string(),
                    key_file: reply["key_file"].as_str().unwrap_or("").to_string(),
                });
                self.new_username.clear();
                let _ = self.fetch_users();
                self.note(format!("Usuario '{}' creado exitosamente", username), false);
            }
            Err(e) => self.note(e, true),
        }
    }

    // ---------- Vistas ----------

    fn login_view(&mut self, ui: &mut egui::Ui) {
        ui.add_space(20.0);
        ui.label("Su identidad es su clave privada (keys/<usuario>.key). Escriba su usuario:");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Usuario:");
            let response = ui.text_edit_singleline(&mut self.login_user);
            if ui.button("Entrar").clicked()
                || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
            {
                self.login();
            }
        });
    }

    fn main_view(&mut self, ui: &mut egui::Ui) {
        let user = self
            .session
            .as_ref()
            .map(|s| s.user.clone())
            .unwrap_or_default();

        let role_label = match self.role.as_str() {
            "admin" => "Administrador",
            "analista" => "Analista",
            _ => "Reportante",
        };

        // Barra superior
        ui.horizontal(|ui| {
            ui.label(format!("👤 {} ({})", user, role_label));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🚪 Cerrar sesión").clicked() {
                    self.session = None;
                    self.tickets.clear();
                    self.users.clear();
                    self.role.clear();
                    self.created_info = None;
                    self.tab = Tab::Tickets;
                    self.message = String::from("Sesión cerrada");
                    self.is_error = false;
                }
            });
        });

        if self.session.is_none() {
            return;
        }

        // Pestañas (solo mostrar Admin si es admin)
        ui.separator();
        ui.horizontal(|ui| {
            if ui
                .selectable_label(self.tab == Tab::Tickets, "📋 Tickets")
                .clicked()
            {
                self.tab = Tab::Tickets;
            }
            if self.is_admin() {
                if ui
                    .selectable_label(self.tab == Tab::Admin, "⚙ Gestión de usuarios")
                    .clicked()
                {
                    self.tab = Tab::Admin;
                    if self.users.is_empty() {
                        let _ = self.fetch_users();
                    }
                }
            }
        });
        ui.separator();

        match self.tab {
            Tab::Tickets => self.tickets_view(ui),
            Tab::Admin => self.admin_view(ui),
        }
    }

    fn tickets_view(&mut self, ui: &mut egui::Ui) {
        // Formulario de envío
        ui.label(egui::RichText::new("Nuevo reporte").strong());
        egui::Grid::new("formulario").num_columns(2).show(ui, |ui| {
            ui.label("Título:");
            ui.text_edit_singleline(&mut self.title);
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
            if ui.button("📤 Enviar reporte").clicked() {
                self.submit();
            }
            if ui.button("🔄 Actualizar").clicked() {
                match self.fetch() {
                    Ok(()) => {
                        let n = self.tickets.len();
                        self.note(format!("{} tickets visibles", n), false);
                    }
                    Err(e) => self.note(e, true),
                }
            }
        });

        ui.separator();

        // Título de la tabla según rol
        let table_title = if self.is_admin() || self.role == "analista" {
            "Todos los tickets"
        } else {
            "Mis reportes"
        };
        ui.label(egui::RichText::new(table_title).strong());

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("mis_tickets")
                .striped(true)
                .num_columns(8)
                .show(ui, |ui| {
                    for h in [
                        "#", "Fecha", "Título", "Severidad", "Reporter", "Estado", "Asignado a",
                        "Resolución",
                    ] {
                        ui.label(egui::RichText::new(h).strong());
                    }
                    ui.end_row();

                    for t in &self.tickets {
                        ui.label(t.id.to_string());
                        ui.label(format_utc(t.created_at));
                        ui.label(&t.title);
                        ui.label(&t.severity);
                        ui.label(&t.reporter);
                        ui.label(&t.status);
                        ui.label(t.assignee.as_deref().unwrap_or("-"));
                        ui.label(t.resolution.as_deref().unwrap_or("-"));
                        ui.end_row();
                    }
                });
        });
    }

    fn admin_view(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Crear nuevo usuario").strong());
        ui.add_space(4.0);

        egui::Grid::new("crear_usuario").num_columns(2).show(ui, |ui| {
            ui.label("Nombre de usuario:");
            ui.text_edit_singleline(&mut self.new_username);
            ui.end_row();

            ui.label("Rol:");
            egui::ComboBox::from_id_salt("nuevo_rol")
                .selected_text(self.new_role.clone())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.new_role, String::from("reportante"), "Reportante");
                    ui.selectable_value(&mut self.new_role, String::from("analista"), "Analista");
                    ui.selectable_value(&mut self.new_role, String::from("admin"), "Administrador");
                });
            ui.end_row();
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("➕ Crear usuario").clicked() {
                self.create_user();
            }
            if ui.button("🔄 Actualizar lista").clicked() {
                match self.fetch_users() {
                    Ok(()) => {
                        self.note(format!("{} usuarios registrados", self.users.len()), false);
                    }
                    Err(e) => self.note(e, true),
                }
            }
        });

        // Mostrar info de la clave del usuario recién creado
        let mut dismiss = false;
        if let Some(info) = &self.created_info {
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.label(
                    egui::RichText::new(format!("🔑 Credenciales de '{}'", info.username))
                        .strong()
                        .color(egui::Color32::from_rgb(0, 180, 0)),
                );
                ui.label(format!("Rol: {}", info.role));
                ui.label(format!("Clave pública: {}", info.public_key));
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("⚠ Clave privada (entregar al usuario de forma segura):")
                        .color(egui::Color32::from_rgb(255, 180, 0)),
                );
                ui.monospace(&info.private_key);
                ui.add_space(4.0);
                ui.label(format!("Archivo guardado en: {}", info.key_file));
                ui.label("El usuario debe copiar este archivo a su carpeta keys/ para usar el sistema.");
                if ui.button("✓ Entendido, cerrar").clicked() {
                    dismiss = true;
                }
            });
        }
        if dismiss {
            self.created_info = None;
        }

        ui.separator();
        ui.label(egui::RichText::new("Usuarios registrados").strong());

        egui::ScrollArea::vertical()
            .id_salt("scroll_users")
            .show(ui, |ui| {
                egui::Grid::new("tabla_usuarios")
                    .striped(true)
                    .num_columns(3)
                    .show(ui, |ui| {
                        for h in ["Usuario", "Rol", "Clave pública"] {
                            ui.label(egui::RichText::new(h).strong());
                        }
                        ui.end_row();

                        for u in &self.users {
                            ui.label(&u.user);
                            let role_label = match u.role.as_str() {
                                "admin" => "Administrador",
                                "analista" => "Analista",
                                _ => "Reportante",
                            };
                            ui.label(role_label);
                            ui.monospace(format!("{}…", &u.public_key[..16.min(u.public_key.len())]));
                            ui.end_row();
                        }
                    });
            });
    }
}

impl eframe::App for PortalApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Portal de reportes — Ticket Chain");

            let color = if self.is_error {
                egui::Color32::RED
            } else {
                egui::Color32::GREEN
            };
            ui.colored_label(color, &self.message);
            ui.separator();

            if self.session.is_some() {
                self.main_view(ui);
            } else {
                self.login_view(ui);
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "Portal de reportes — Ticket Chain",
        eframe::NativeOptions::default(),
        Box::new(|cc| Ok(Box::new(PortalApp::new(cc)))),
    )
}
