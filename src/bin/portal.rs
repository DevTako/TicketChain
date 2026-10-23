#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use serde::Deserialize;

use ticket_chain::client::{format_utc, Session};
use ticket_chain::{paths, server, validate_command, Command, ALLOWED_SEVERITIES};

// Solo los campos que el portal muestra; serde ignora el resto.
#[derive(Deserialize, Clone)]
struct TicketView {
    id: u64,
    title: String,
    #[serde(default)]
    description: String,
    severity: String,
    created_at: u64,
    status: String,
    reporter: String,
    assignee: Option<String>,
    #[serde(default)]
    resolved_by: Option<String>,
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
    Analista,
    Admin,
}

#[derive(PartialEq, Clone, Copy)]
enum StatusFilter {
    Todos,
    SinAceptar, // abierto
    EnProgreso, // asignado
    Solucionado, // resuelto
}

fn status_display_name(status: &str) -> &'static str {
    match status {
        "abierto" => "Aún sin aceptar",
        "asignado" => "En progreso",
        "resuelto" => "Solucionado",
        _ => "Desconocido",
    }
}

fn status_color(status: &str) -> egui::Color32 {
    match status {
        "abierto" => egui::Color32::from_rgb(235, 175, 30), // Amarillo / naranja
        "asignado" => egui::Color32::from_rgb(60, 160, 240), // Azul cielo
        "resuelto" => egui::Color32::from_rgb(50, 205, 90),  // Verde
        _ => egui::Color32::GRAY,
    }
}

fn severity_color(severity: &str) -> egui::Color32 {
    match severity {
        "Crítica" => egui::Color32::from_rgb(230, 60, 60),
        "Alta" => egui::Color32::from_rgb(240, 130, 30),
        "Media" => egui::Color32::from_rgb(220, 190, 30),
        "Baja" => egui::Color32::from_rgb(90, 170, 230),
        _ => egui::Color32::GRAY,
    }
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

    // Bandeja de analista
    status_filter: StatusFilter,
    analyst_search: String,
    only_my_assigned: bool,
    resolving_ticket_id: Option<u64>,
    resolution_input: String,

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
            status_filter: StatusFilter::Todos,
            analyst_search: String::new(),
            only_my_assigned: false,
            resolving_ticket_id: None,
            resolution_input: String::new(),
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

    fn is_analista(&self) -> bool {
        self.role == "analista" || self.role == "admin"
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

                        // Si es analista o admin, abrir por defecto la bandeja de gestión de tickets
                        if self.is_analista() {
                            self.tab = Tab::Analista;
                        } else {
                            self.tab = Tab::Tickets;
                        }

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

    fn assign_ticket(&mut self, ticket_id: u64) {
        let result = match &self.session {
            Some(s) => s.asignar(ticket_id),
            None => return,
        };

        match result {
            Ok(_) => {
                match self.fetch() {
                    Ok(()) => self.note(
                        format!("Ticket #{} aceptado con éxito. Estado: 'En progreso'", ticket_id),
                        false,
                    ),
                    Err(e) => self.note(
                        format!("Ticket #{} asignado, pero error al actualizar: {}", ticket_id, e),
                        true,
                    ),
                }
            }
            Err(e) => self.note(format!("Error al aceptar ticket #{}: {}", ticket_id, e), true),
        }
    }

    fn resolve_ticket(&mut self, ticket_id: u64, note: String) {
        let trimmed_note = note.trim();
        if trimmed_note.is_empty() {
            self.note(String::from("La nota de solución no puede estar vacía"), true);
            return;
        }

        let result = match &self.session {
            Some(s) => s.resolver(ticket_id, trimmed_note),
            None => return,
        };

        match result {
            Ok(_) => {
                self.resolving_ticket_id = None;
                self.resolution_input.clear();
                match self.fetch() {
                    Ok(()) => self.note(
                        format!("Ticket #{} marcado como 'Solucionado' con éxito", ticket_id),
                        false,
                    ),
                    Err(e) => self.note(
                        format!("Ticket #{} solucionado, pero error al actualizar: {}", ticket_id, e),
                        true,
                    ),
                }
            }
            Err(e) => self.note(format!("Error al solucionar ticket #{}: {}", ticket_id, e), true),
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
                    self.resolving_ticket_id = None;
                    self.resolution_input.clear();
                    self.tab = Tab::Tickets;
                    self.message = String::from("Sesión cerrada");
                    self.is_error = false;
                }
            });
        });

        if self.session.is_none() {
            return;
        }

        // Pestañas
        ui.separator();
        ui.horizontal(|ui| {
            let tickets_title = if self.is_analista() {
                "📝 Enviar reporte / Ver todos"
            } else {
                "📋 Mis reportes"
            };
            if ui
                .selectable_label(self.tab == Tab::Tickets, tickets_title)
                .clicked()
            {
                self.tab = Tab::Tickets;
            }

            if self.is_analista() {
                if ui
                    .selectable_label(self.tab == Tab::Analista, "📥 Bandeja de Analista")
                    .clicked()
                {
                    self.tab = Tab::Analista;
                }
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
            Tab::Analista => {
                if self.is_analista() {
                    self.analyst_view(ui);
                } else {
                    self.tab = Tab::Tickets;
                    self.tickets_view(ui);
                }
            }
            Tab::Admin => self.admin_view(ui),
        }
    }

    fn analyst_view(&mut self, ui: &mut egui::Ui) {
        let current_user = self
            .session
            .as_ref()
            .map(|s| s.user.clone())
            .unwrap_or_default();

        ui.horizontal(|ui| {
            ui.heading("📥 Bandeja de Tickets Recibidos");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🔄 Actualizar tickets").clicked() {
                    match self.fetch() {
                        Ok(()) => {
                            self.note(format!("{} tickets cargados", self.tickets.len()), false);
                        }
                        Err(e) => self.note(e, true),
                    }
                }
            });
        });

        ui.label(
            "Visualice y gestione los tickets enviados por los reportantes. Controle el estado de cada ticket: Aún sin aceptar → En progreso → Solucionado.",
        );
        ui.add_space(6.0);

        // Contadores
        let total_count = self.tickets.len();
        let sin_aceptar_count = self.tickets.iter().filter(|t| t.status == "abierto").count();
        let en_progreso_count = self.tickets.iter().filter(|t| t.status == "asignado").count();
        let solucionado_count = self.tickets.iter().filter(|t| t.status == "resuelto").count();

        // Barra de botones de filtro por estado
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Estado:").strong());

            let all_label = format!("Todos ({})", total_count);
            if ui
                .selectable_label(self.status_filter == StatusFilter::Todos, all_label)
                .clicked()
            {
                self.status_filter = StatusFilter::Todos;
            }

            let sin_aceptar_label = format!("🟡 Aún sin aceptar ({})", sin_aceptar_count);
            if ui
                .selectable_label(
                    self.status_filter == StatusFilter::SinAceptar,
                    sin_aceptar_label,
                )
                .clicked()
            {
                self.status_filter = StatusFilter::SinAceptar;
            }

            let en_progreso_label = format!("🔵 En progreso ({})", en_progreso_count);
            if ui
                .selectable_label(
                    self.status_filter == StatusFilter::EnProgreso,
                    en_progreso_label,
                )
                .clicked()
            {
                self.status_filter = StatusFilter::EnProgreso;
            }

            let solucionado_label = format!("🟢 Solucionado ({})", solucionado_count);
            if ui
                .selectable_label(
                    self.status_filter == StatusFilter::Solucionado,
                    solucionado_label,
                )
                .clicked()
            {
                self.status_filter = StatusFilter::Solucionado;
            }
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("🔍 Buscar:");
            ui.text_edit_singleline(&mut self.analyst_search);
            if !self.analyst_search.is_empty() && ui.button("✖").clicked() {
                self.analyst_search.clear();
            }
            ui.separator();
            ui.checkbox(&mut self.only_my_assigned, "Solo mis tickets asignados");
        });

        ui.separator();

        let search_query = self.analyst_search.trim().to_lowercase();
        let filtered_tickets: Vec<&TicketView> = self
            .tickets
            .iter()
            .filter(|t| {
                // Filtro por estado
                let status_match = match self.status_filter {
                    StatusFilter::Todos => true,
                    StatusFilter::SinAceptar => t.status == "abierto",
                    StatusFilter::EnProgreso => t.status == "asignado",
                    StatusFilter::Solucionado => t.status == "resuelto",
                };
                if !status_match {
                    return false;
                }

                // Filtro solo mis asignados
                if self.only_my_assigned && t.assignee.as_deref() != Some(&current_user) {
                    return false;
                }

                // Filtro de búsqueda textual
                if !search_query.is_empty() {
                    let id_str = t.id.to_string();
                    let match_id = id_str.contains(&search_query);
                    let match_title = t.title.to_lowercase().contains(&search_query);
                    let match_rep = t.reporter.to_lowercase().contains(&search_query);
                    let match_desc = t.description.to_lowercase().contains(&search_query);
                    if !match_id && !match_title && !match_rep && !match_desc {
                        return false;
                    }
                }

                true
            })
            .collect();

        if filtered_tickets.is_empty() {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("No hay tickets que coincidan con los filtros actuales.")
                        .italics()
                        .size(14.0),
                );
            });
            return;
        }

        // Listado de tickets
        let mut assign_target_id = None;
        let mut start_resolving_id = None;
        let mut cancel_resolving = false;
        let mut finish_resolve_data = None;

        egui::ScrollArea::vertical()
            .id_salt("scroll_analyst_tickets")
            .show(ui, |ui| {
                for t in &filtered_tickets {
                    ui.group(|ui| {
                        ui.set_width(ui.available_width());

                        // Fila superior: ID, severidad, reportante, fecha y badge de estado
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("#{}", t.id))
                                    .strong()
                                    .size(15.0),
                            );
                            ui.colored_label(
                                severity_color(&t.severity),
                                format!("● Severidad: {}", t.severity),
                            );
                            ui.separator();
                            ui.label(format!("👤 Reportante: {}", t.reporter));
                            ui.separator();
                            ui.label(format!("🕒 {}", format_utc(t.created_at)));

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let badge_label = format!("● {}", status_display_name(&t.status));
                                    ui.colored_label(
                                        status_color(&t.status),
                                        egui::RichText::new(badge_label).strong().size(13.0),
                                    );
                                },
                            );
                        });

                        ui.add_space(4.0);
                        // Título
                        ui.label(egui::RichText::new(&t.title).strong().size(14.0));

                        // Descripción completa si existe
                        if !t.description.is_empty() {
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new(&t.description)
                                    .color(egui::Color32::from_gray(210)),
                            );
                        }

                        // Asignación
                        if let Some(assignee) = &t.assignee {
                            ui.add_space(2.0);
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Asignado a:").italics());
                                if assignee == &current_user {
                                    ui.label(
                                        egui::RichText::new(format!("{} (Tú)", assignee))
                                            .color(egui::Color32::from_rgb(80, 180, 255))
                                            .strong(),
                                    );
                                } else {
                                    ui.label(
                                        egui::RichText::new(assignee)
                                            .color(egui::Color32::from_gray(180)),
                                    );
                                }
                            });
                        }

                        // Resolución si está solucionado
                        if t.status == "resuelto" {
                            ui.add_space(4.0);
                            ui.group(|ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("💡 Solución aplicada:")
                                            .strong()
                                            .color(egui::Color32::from_rgb(60, 205, 100)),
                                    );
                                    if let Some(by) = &t.resolved_by {
                                        ui.label(format!("(Resuelto por: {})", by));
                                    }
                                });
                                ui.label(
                                    t.resolution
                                        .as_deref()
                                        .unwrap_or("Sin nota de resolución registrada."),
                                );
                            });
                        }

                        // Zona de acciones de cambio de estado
                        ui.add_space(6.0);
                        ui.separator();
                        ui.horizontal(|ui| {
                            match t.status.as_str() {
                                "abierto" => {
                                    if t.reporter == current_user {
                                        ui.label(
                                            egui::RichText::new(
                                                "⚠ Principio de 4 ojos: No puedes autoasignarte un ticket que reportaste tú mismo.",
                                            )
                                            .color(egui::Color32::from_rgb(255, 175, 40))
                                            .italics(),
                                        );
                                    } else {
                                        if ui
                                            .button(
                                                egui::RichText::new(
                                                    "✋ Aceptar ticket y poner 'En progreso'",
                                                )
                                                .strong(),
                                            )
                                            .clicked()
                                        {
                                            assign_target_id = Some(t.id);
                                        }
                                    }
                                }
                                "asignado" => {
                                    if t.assignee.as_deref() == Some(&current_user) {
                                        if self.resolving_ticket_id == Some(t.id) {
                                            ui.vertical(|ui| {
                                                ui.label(
                                                    egui::RichText::new(
                                                        "📝 Escriba la solución aplicada para cerrar el ticket:",
                                                    )
                                                    .strong(),
                                                );
                                                ui.text_edit_multiline(&mut self.resolution_input);
                                                ui.horizontal(|ui| {
                                                    if ui
                                                        .button(
                                                            egui::RichText::new(
                                                                "✅ Confirmar y marcar como 'Solucionado'",
                                                            )
                                                            .strong(),
                                                        )
                                                        .clicked()
                                                    {
                                                        finish_resolve_data = Some((
                                                            t.id,
                                                            self.resolution_input.clone(),
                                                        ));
                                                    }
                                                    if ui.button("Cancelar").clicked() {
                                                        cancel_resolving = true;
                                                    }
                                                });
                                            });
                                        } else {
                                            if ui
                                                .button(
                                                    egui::RichText::new(
                                                        "✅ Resolver y marcar como 'Solucionado'",
                                                    )
                                                    .strong(),
                                                )
                                                .clicked()
                                            {
                                                start_resolving_id = Some(t.id);
                                            }
                                        }
                                    } else {
                                        let who = t.assignee.as_deref().unwrap_or("otro analista");
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "En atención por {}. Solo el analista asignado puede resolverlo.",
                                                who
                                            ))
                                            .italics()
                                            .color(egui::Color32::from_gray(160)),
                                        );
                                    }
                                }
                                "resuelto" => {
                                    ui.label(
                                        egui::RichText::new(
                                            "✔ Ticket solucionado satisfactoriamente y sellado en blockchain.",
                                        )
                                        .color(egui::Color32::from_rgb(70, 205, 100))
                                        .italics(),
                                    );
                                }
                                _ => {}
                            }
                        });
                    });
                    ui.add_space(6.0);
                }
            });

        if let Some(id) = assign_target_id {
            self.assign_ticket(id);
        }
        if let Some(id) = start_resolving_id {
            self.resolving_ticket_id = Some(id);
            self.resolution_input.clear();
        }
        if cancel_resolving {
            self.resolving_ticket_id = None;
            self.resolution_input.clear();
        }
        if let Some((id, note)) = finish_resolve_data {
            self.resolve_ticket(id, note);
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
            "Todos los tickets registrados"
        } else {
            "Mis reportes"
        };
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(table_title).strong());
            if self.is_analista() {
                ui.label(
                    egui::RichText::new(
                        "(Para atender, asignar y solucionar tickets, use la pestaña '📥 Bandeja de Analista')",
                    )
                    .color(egui::Color32::from_rgb(80, 180, 255))
                    .italics(),
                );
            }
        });

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
                        ui.colored_label(severity_color(&t.severity), &t.severity);
                        ui.label(&t.reporter);
                        ui.colored_label(status_color(&t.status), status_display_name(&t.status));
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
    paths::ensure_environment();
    server::ensure_server_running(
        &paths::server_bind(),
        &paths::data_path("chain.json"),
        &paths::data_path("users.json"),
    );

    let mut options = eframe::NativeOptions::default();
    options.viewport = egui::ViewportBuilder::default()
        .with_inner_size([1020.0, 720.0])
        .with_min_inner_size([820.0, 520.0]);

    eframe::run_native(
        "Portal de reportes — Ticket Chain",
        options,
        Box::new(|cc| Ok(Box::new(PortalApp::new(cc)))),
    )
}
