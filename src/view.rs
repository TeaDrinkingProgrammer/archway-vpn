//! What the window shows: top bar, connection list, the status card with Connect, the editor or the connection
//! details, the settings page and the log. The state and what the buttons do live in main.rs.

use crate::diag::{Diag, Fix};
use crate::form::{self, DraftOwner, Drafts, Field, Look, WIDE};
use crate::net::{DhGroup, Encryption, Hash, Ipv4Net, Keepalive, LoginTimeout, Mtu, Proposal};
use crate::theme::{self, BannerKind, PillKind, Tone, icon};
use crate::*;
use eframe::egui::{self, Align, Color32, Layout, Margin, RichText, Sense, Stroke, Ui, vec2};

/// A connection in the list.
const ROW_HEIGHT: f32 = 58.0;
/// Where the name and gateway start, right of the plug icon.
const ROW_TEXT_X: f32 = 44.0;
/// What each of the selected row's buttons takes: the button and the gap after it.
const ROW_BUTTON: f32 = theme::SMALL_BUTTON + 2.0;
/// Right of the status card's text: the spinner slot, the big button and the gaps around them.
const ACTION_ROOM: f32 = theme::ACTION_SIZE.x + 22.0 + 32.0;
/// More proposal rows than this don't fit the card.
const MAX_PROPOSALS: usize = 4;
/// Of the DH groups this client doesn't support, the first ones (1, 2, 5) are shown disabled, so a setup copied from
/// FortiClient is recognisable; the rest would crowd the row.
const DH_UNSUPPORTED_SHOWN: usize = 3;
/// The narrowest a stat card can be: "255.255.255.255" in the 16 px mono font, a gap and the copy button.
const STAT_MIN: f32 = 190.0;
/// The gap between two fields side by side.
const FIELD_GAP: f32 = 18.0;
/// Help under a field a connect error's button pointed at.
const FIX_HELP: &str = "Enter it here, then Save and connect again.";
const PSK_HELP: &str = "Kept in your desktop keyring, never in the connection file.";

impl App {
    pub(crate) fn top_bar(&mut self, root: &mut Ui, problems: &[Problem], save_key: &egui::KeyboardShortcut) {
        let t = theme::tokens(root);
        egui::Panel::top("top")
            .frame(egui::Frame::new().fill(t.side).inner_margin(Margin::symmetric(16, 10)).stroke(Stroke::new(1.0, t.border)))
            .show_separator_line(false)
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    theme::logo(ui, 28.0);
                    ui.label(theme::title(ui, "Archway", 16.0));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if theme::icon_button(ui, icon::SETTINGS, "Settings", self.show_settings).clicked() {
                            self.show_settings = !self.show_settings;
                            self.settings_error = None;
                        }
                        if theme::icon_button(ui, icon::TERMINAL, "Log", self.cfg.show_log).clicked() {
                            self.cfg.show_log = !self.cfg.show_log;
                        }
                        let (rect, _) = ui.allocate_exact_size(vec2(9.0, 24.0), Sense::hover());
                        ui.painter().vline(rect.center().x, rect.y_range(), Stroke::new(1.0, t.border));
                        if self.unsaved() {
                            let shortcut = ui.ctx().format_shortcut(save_key);
                            let save = theme::solid(ui, problems.is_empty(), Tone::Primary, icon::SAVE, "Save Changes")
                                .on_hover_text(format!("Save the settings ({shortcut})"))
                                .on_disabled_hover_text(FIX_FIRST);
                            if save.clicked() {
                                self.save();
                            }
                            ui.label(theme::medium(ui, "Unsaved changes", 13.0).color(t.warning));
                        } else {
                            theme::labelled(ui.label(theme::with_icon(ui, icon::CHECK, "All changes saved", 13.0, t.weak, false)), "All changes saved");
                        }
                    });
                });
            });
    }

    pub(crate) fn connection_list(&mut self, root: &mut Ui, problems: &[Problem]) {
        let t = theme::tokens(root);
        egui::Panel::left("profiles")
            .resizable(true)
            .default_size(250.0)
            .size_range(200.0..=400.0)
            .frame(egui::Frame::new().fill(t.side).inner_margin(Margin { left: 12, right: 12, top: 14, bottom: 12 }).stroke(Stroke::new(1.0, t.border)))
            .show_separator_line(false)
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    theme::eyebrow(ui, "Connections");
                });
                ui.add_space(4.0);
                let busy = self.busy();
                egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 8.0;
                    for i in 0..self.cfg.profiles.len() {
                        let id = &self.cfg.profiles[i].id;
                        let marked = problems.iter().any(|x| matches!(&x.owner, DraftOwner::Profile(o) if o == id));
                        if self.connection_row(ui, i, marked, busy).clicked() && !busy && i != self.cfg.selected {
                            self.cfg.selected = i;
                            self.fix_focus = None;
                        }
                    }
                    ui.add_space(6.0);
                    if theme::list_button(ui, !busy, icon::PLUS, "New Connection").clicked() {
                        self.add_profile(Profile::default());
                    }
                });
            });
    }

    /// One connection in the list: plug icon (green when connected), name, gateway, ⚠ when it has a problem, and for
    /// the selected one the Duplicate, Share and Delete buttons.
    fn connection_row(&mut self, ui: &mut Ui, i: usize, marked: bool, busy: bool) -> egui::Response {
        let t = theme::tokens(ui);
        let p = &self.cfg.profiles[i];
        let selected = i == self.cfg.selected;
        let buttons = if selected && !busy { self.action_count() } else { 0 };
        let (rect, r) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_HEIGHT), if busy { Sense::hover() } else { Sense::click() });
        let shown = self.shown_name(i);
        let label = if marked { format!("⚠ {shown}") } else { shown.clone() };
        r.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, !busy, selected, &label));
        let painter = ui.painter();
        if selected {
            painter.rect_filled(rect, egui::CornerRadius::same(10), t.selected);
            painter.rect_filled(egui::Rect::from_min_size(rect.min + vec2(0.0, 15.0), vec2(3.0, 28.0)), egui::CornerRadius::same(2), t.text);
        } else if r.hovered() && !busy {
            painter.rect_filled(rect, egui::CornerRadius::same(10), t.hover);
        }
        if r.has_focus() {
            painter.rect_stroke(rect, egui::CornerRadius::same(10), Stroke::new(2.0, t.focus), egui::StrokeKind::Inside);
        }
        let ours = busy && i == self.profile_connected;
        let (plug, plug_color) = match self.state {
            State::Connected if ours => (icon::PLUG_ZAP, t.success),
            _ if ours => (icon::PLUG, t.warning),
            _ => (icon::PLUG, t.weak),
        };
        let fit = |ui: &Ui, text: RichText, room: f32| egui::WidgetText::from(text).into_galley(ui, Some(egui::TextWrapMode::Truncate), room, egui::TextStyle::Body);
        let room = rect.width() - ROW_TEXT_X - 12.0;
        let warn_room = if marked { 22.0 } else { 0.0 };
        // the buttons sit on the name's line, so the gateway under it keeps the full width
        let name = fit(ui, theme::title(ui, shown, 14.5), room - buttons as f32 * ROW_BUTTON - warn_room);
        let gateway = gateway_text(p);
        let sub = fit(ui, RichText::new(if gateway.is_empty() { "No gateway yet".to_string() } else { gateway }).size(12.5).color(t.weak), room);
        let plug = fit(ui, theme::glyph(ui, plug, 20.0, plug_color), f32::INFINITY);
        let painter = ui.painter();
        painter.galley(rect.left_center() + vec2(14.0, -plug.size().y / 2.0), plug, t.weak);
        painter.galley(rect.left_top() + vec2(ROW_TEXT_X, 9.0), name, t.text);
        painter.galley(rect.left_bottom() + vec2(ROW_TEXT_X, -9.0 - sub.size().y), sub, t.weak);
        // right-aligned on the name's line; the ⚠ goes left of them
        let name_line = rect.top() + 18.0;
        let buttons_left = rect.right() - 8.0 - buttons as f32 * ROW_BUTTON;
        if marked {
            let warn = fit(ui, theme::glyph(ui, icon::TRIANGLE_ALERT, 17.0, t.warning), f32::INFINITY);
            ui.painter().galley(egui::pos2(buttons_left - 6.0 - warn.size().x, name_line - warn.size().y / 2.0), warn, t.warning);
        }
        if buttons > 0 {
            let area = egui::Rect::from_min_max(egui::pos2(buttons_left, name_line - 15.0), egui::pos2(rect.right() - 8.0, name_line + 15.0));
            // a child outside the list's layout: placing it must not move the list's cursor
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(area).layout(Layout::left_to_right(Align::Center)));
            child.spacing_mut().item_spacing.x = ROW_BUTTON - theme::SMALL_BUTTON;
            self.connection_actions(&mut child);
        }
        r
    }

    /// Connection `i`'s name as it's typed (in the title or the Connection Name field), even while it doesn't parse.
    fn shown_name(&self, i: usize) -> String {
        let p = &self.cfg.profiles[i];
        match self.drafts.text(&(DraftOwner::Profile(p.id.clone()), Field::Name)) {
            Some(t) if t.trim().is_empty() => "Unnamed connection".into(),
            Some(t) => t.to_owned(),
            None => p.name.to_string(),
        }
    }

    /// How many buttons `connection_actions` shows: Delete only when another connection is left.
    fn action_count(&self) -> usize {
        if self.cfg.profiles.len() > 1 { 3 } else { 2 }
    }

    /// Duplicate, Share and Delete for the selected connection.
    fn connection_actions(&mut self, ui: &mut Ui) {
        if theme::small_icon_button(ui, true, icon::COPY, "Duplicate", Color32::PLACEHOLDER).clicked() {
            self.add_profile(self.cfg.profiles[self.cfg.selected].duplicate());
        }
        // also while connected: it only shows the saved file
        let share = theme::small_icon_button(ui, !self.unsaved(), icon::SHARE, "Share", Color32::PLACEHOLDER)
            .on_disabled_hover_text("Save first, so the file matches what you see.")
            .on_hover_text(SHARE_HELP);
        if share.clicked() {
            self.share_profile();
        }
        if self.action_count() > 2 && theme::small_icon_button(ui, true, icon::TRASH, "Delete", theme::tokens(ui).danger).clicked() {
            self.confirm_delete = true;
        }
    }

    /// The open confirmation, if any: delete the selected connection, or regenerate the client UID.
    pub(crate) fn dialogs(&mut self, ctx: &egui::Context) {
        if self.confirm_delete {
            let title = format!("Delete “{}”?", self.shown_name(self.cfg.selected));
            let body = "The connection, its PSK and its saved password are removed when you click Save.";
            match confirm(ctx, "delete_profile", &title, body, (Tone::DangerFill, "Delete Connection")) {
                Some(true) => {
                    let gone = self.cfg.profiles.remove(self.cfg.selected);
                    self.drafts.remove_owner(&DraftOwner::Profile(gone.id));
                    self.cfg.selected = self.cfg.selected.min(self.cfg.profiles.len() - 1);
                    self.confirm_delete = false;
                    self.fix_focus = None;
                }
                Some(false) => self.confirm_delete = false,
                None => {}
            }
        }
        if self.confirm_regen {
            let body = "The FortiGate will see this installation as a new device. The new UID is used after you click Save.";
            if let Some(yes) = confirm(ctx, "regenerate_uid", "Regenerate client UID?", body, (Tone::Primary, "Regenerate")) {
                self.regenerate_uid(yes);
            }
        }
    }

    pub(crate) fn log_drawer(&mut self, root: &mut Ui) {
        if !self.cfg.show_log {
            return;
        }
        let t = theme::tokens(root);
        egui::Panel::bottom("log")
            .resizable(true)
            .default_size(190.0)
            .frame(egui::Frame::new().fill(t.side).inner_margin(Margin::symmetric(16, 10)).stroke(Stroke::new(1.0, t.border)))
            .show_separator_line(false)
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(theme::glyph(ui, icon::TERMINAL, 17.0, t.weak));
                    ui.label(theme::title(ui, "Log", 14.5));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if theme::icon_button(ui, icon::X, "Close log", false).clicked() {
                            self.cfg.show_log = false;
                        }
                        if theme::quiet(ui, icon::TRASH, "Clear").clicked() {
                            self.log.clear();
                        }
                        theme::copy_button(ui, egui::Id::new("copy-log"), || self.log.join("\n"), "Copy", Some(96.0));
                    });
                });
                egui::Frame::new().fill(t.surface).stroke(Stroke::new(1.0, t.border)).corner_radius(8).inner_margin(Margin::symmetric(10, 8)).show(ui, |ui| {
                    let font = egui::FontId::monospace(12.5);
                    let row_height = ui.fonts_mut(|f| f.row_height(&font));
                    if self.log.is_empty() {
                        ui.label(theme::weak(ui, "Nothing logged yet. Connect to see what happens."));
                    }
                    // only the rows in view are laid out: a verbose connect logs thousands of lines; long lines scroll
                    // sideways instead of wrapping, so every row has the same height
                    egui::ScrollArea::both().stick_to_bottom(true).auto_shrink([false, false]).show_rows(ui, row_height, self.log.len(), |ui, rows| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        for l in &self.log[rows] {
                            let c = if l.starts_with("ERROR") { t.danger } else if l.starts_with("===") { t.text } else { t.secondary };
                            ui.add(egui::Label::new(RichText::new(l).font(font.clone()).color(c)).extend());
                        }
                    });
                });
            });
    }

    pub(crate) fn main_view(&mut self, root: &mut Ui, problems: &[Problem]) {
        let t = theme::tokens(root);
        let ctx = root.ctx().clone();
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(t.surface).inner_margin(Margin { left: 24, right: 24, top: 20, bottom: 12 }))
            .show(root, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 14.0;
                    if self.show_settings {
                        self.settings_page(ui);
                        return;
                    }
                    self.status_card(ui, &ctx, problems);
                    self.error_banners(ui);
                    self.sign_in_help(ui);
                    if self.busy() {
                        self.connection_details(ui);
                    } else {
                        self.profile_editor(ui);
                    }
                });
            });
    }

    /// The connect error, with a button to the field when it's a missing value, then save and share errors.
    fn error_banners(&mut self, ui: &mut Ui) {
        if let Some(e) = self.error.clone() {
            let fix = Diag::parse(&e).and_then(|d| d.fix()).filter(|_| !self.busy());
            let act = theme::error_banner(ui, &e, fix.map(Fix::button), true);
            if act.dismiss {
                self.error = None;
            }
            if act.fix
                && let Some(fix) = fix
            {
                self.error = None;
                self.fix_focus = Some(fix);
                self.fix_scroll = true;
                let target = self.fix_target(fix);
                ui.memory_mut(|m| m.request_focus(target));
            }
        }
        for e in [&self.save_error, &self.share_error].into_iter().flatten() {
            theme::error_banner(ui, e, None, false);
        }
    }

    /// The widget a fix button focuses.
    fn fix_target(&self, fix: Fix) -> egui::Id {
        let p = &self.cfg.profiles[self.cfg.selected];
        let owner = DraftOwner::Profile(p.id.clone());
        match fix {
            Fix::Gateway => form::field_id(&(owner, Field::Gateway)),
            Fix::Psk => secret_id(&owner, "psk"),
            Fix::Credentials if p.auth.username.is_none() => form::field_id(&(owner, Field::Username)),
            Fix::Credentials => secret_id(&owner, "password"),
        }
    }

    /// State, connection name and gateway, and the button for what to do next.
    fn status_card(&mut self, ui: &mut Ui, ctx: &egui::Context, problems: &[Problem]) {
        let t = theme::tokens(ui);
        let busy = self.busy();
        let p = &self.cfg.profiles[if busy { self.profile_connected } else { self.cfg.selected }];
        let (name, gateway, description) = (p.name.to_string(), gateway_text(p), p.description.to_string());
        let auth = if p.sso.enabled {
            "SSO"
        } else if p.auth.mode == UserAuth::Eap {
            "username and password"
        } else {
            "pre-shared key only"
        };
        let state = match (self.state, self.since) {
            (State::Connected, Some(since)) => format!("Connected · {}", duration(since.elapsed().as_secs())),
            (s, _) => s.label().to_string(),
        };
        let kind = match self.state {
            State::Idle => PillKind::Idle,
            State::Connected => PillKind::Connected,
            _ => PillKind::Busy,
        };
        theme::card(ui, |ui| {
            ui.horizontal_top(|ui| {
                let left = ui.vertical(|ui| {
                    ui.set_width((ui.available_width() - ACTION_ROOM).max(200.0));
                    ui.spacing_mut().item_spacing.y = 6.0;
                    theme::pill(ui, kind, &state);
                    if busy {
                        ui.add(egui::Label::new(theme::title(ui, name, 24.0)).truncate());
                        if !description.is_empty() {
                            ui.add(egui::Label::new(theme::caption(ui, &description).color(t.weak)).truncate());
                        }
                    } else {
                        // the only place to edit them: click to type
                        let i = self.cfg.selected;
                        let owner = DraftOwner::Profile(self.cfg.profiles[i].id.clone());
                        // as wide as the column
                        let w = Some(f32::INFINITY);
                        let p = &mut self.cfg.profiles[i];
                        form::parsed(ui, &mut self.drafts, (owner.clone(), Field::Name), &mut p.name, Look { width: w, inline: Some(24.0), ..Look::hint("Name this connection") })
                            .on_hover_text("Click to rename");
                        form::parsed(ui, &mut self.drafts, (owner, Field::Description), &mut p.description, Look { width: w, inline: Some(14.0), ..Look::hint("Add a description") })
                            .on_hover_text("Click to edit the description");
                    }
                    let place = if gateway.is_empty() { "No gateway yet".to_string() } else { gateway };
                    ui.add(egui::Label::new(theme::with_icon(ui, icon::GLOBE, &format!("{place}  ·  {auth}"), 14.0, t.weak, false)).truncate());
                    self.status_line(ui, problems);
                });
                // as tall as the text, the button centred on it
                let size = vec2(ui.available_width(), left.response.rect.height());
                ui.allocate_ui_with_layout(size, Layout::right_to_left(Align::Center), |ui| {
                    match self.state {
                        State::Idle => {
                            let blocked = self.blocks_connect(problems);
                            if theme::action(ui, !blocked, Tone::Primary, "Connect").on_disabled_hover_text(FIX_FIRST).clicked() {
                                self.connect(ctx);
                            }
                        }
                        State::Connected => {
                            if theme::action(ui, true, Tone::Danger, "Disconnect").clicked() {
                                self.disconnect();
                            }
                        }
                        State::Disconnecting => {
                            theme::action(ui, false, Tone::Danger, "Disconnect");
                        }
                        _ => {
                            if theme::action(ui, true, Tone::Plain, "Cancel").clicked() {
                                self.disconnect();
                            }
                        }
                    }
                    // always there, so the button doesn't move when the spinner appears
                    let (rect, _) = ui.allocate_exact_size(vec2(22.0, 22.0), Sense::hover());
                    match self.state {
                        State::Idle | State::Connected => {}
                        // the browser login can take minutes and the app does nothing meanwhile: a still icon, so the
                        // window isn't redrawn 20 times a second for it
                        State::Authenticating => {
                            ui.put(rect, egui::Label::new(theme::glyph(ui, icon::HOURGLASS, 20.0, t.warning)));
                        }
                        _ => {
                            ui.put(rect, |ui: &mut Ui| theme::spinner(ui, 22.0, t.warning));
                        }
                    }
                });
            });
        });
    }

    /// "⚠ {whose}: {message}" for a problem, naming the connection or Settings.
    fn problem_text(&self, p: &Problem) -> String {
        let whose = match &p.owner {
            DraftOwner::App => "Settings".to_string(),
            DraftOwner::Profile(id) => self.cfg.profiles.iter().position(|x| &x.id == id).map_or_else(String::new, |i| self.shown_name(i)),
        };
        format!("⚠ {whose}: {}", p.message)
    }

    /// One line in the status card that is always there, so a problem appearing doesn't move the page: the first
    /// problem that blocks Save (the rest on hover), or nothing.
    fn status_line(&self, ui: &mut Ui, problems: &[Problem]) {
        let t = theme::tokens(ui);
        ui.horizontal(|ui| {
            ui.set_min_height(20.0);
            ui.spacing_mut().interact_size.y = 0.0;
            match problems {
                // an empty line as tall as a problem's, so one appearing moves nothing
                [] => {
                    ui.label(theme::caption(ui, " "));
                }
                [first, rest @ ..] => {
                    let all = problems.iter().map(|p| self.problem_text(p)).collect::<Vec<_>>().join("\n");
                    // the count first (right to left), so a long first problem is the one that gets cut off
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !rest.is_empty() {
                            ui.label(theme::medium(ui, format!("+{} more", rest.len()), theme::CAPTION).color(t.warning)).on_hover_text(&all);
                        }
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            ui.add(egui::Label::new(RichText::new(self.problem_text(first)).size(theme::CAPTION).color(t.warning)).truncate()).on_hover_text(&all);
                        });
                    });
                }
            }
        });
    }

    /// What the user has to do while connecting: sign in in the browser, or enter the root password.
    fn sign_in_help(&mut self, ui: &mut Ui) {
        let t = theme::tokens(ui);
        if self.state == State::Authenticating && !self.info.saml_url.is_empty() {
            theme::banner(ui, BannerKind::Info, icon::LOG_IN, |ui| {
                ui.label(theme::title(ui, "Finish signing in in your browser.", 16.0));
                ui.label(RichText::new("If no login tab opened, open it here or paste the link into the browser where you're signed in.").color(t.secondary));
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    if theme::solid(ui, true, Tone::Primary, icon::EXTERNAL_LINK, "Open Login Page").on_hover_text(&self.info.saml_url).clicked() {
                        ui.ctx().open_url(egui::OpenUrl::new_tab(&self.info.saml_url));
                    }
                    theme::copy_button(ui, egui::Id::new("copy-login-link"), || self.info.saml_url.clone(), "Copy Link", Some(124.0))
                        .on_hover_text("Paste it into the browser where you're signed in");
                });
            });
        } else if self.state == State::Elevating {
            theme::banner(ui, BannerKind::Info, icon::LOCK, |ui| {
                ui.label(theme::title(ui, "Enter your password in the system prompt.", 16.0));
                ui.label(RichText::new("Setting up the VPN tunnel needs administrator rights.").color(t.secondary));
            });
        } else if self.state == State::Authenticating && self.connect_started.is_some_and(|at| at.elapsed().as_secs() >= 5) {
            let p = &self.cfg.profiles[self.profile_connected];
            let msg = format!("No answer from {}:{} yet. The SSO port may be wrong.", gateway_text(p), p.sso.port);
            theme::banner(ui, BannerKind::Warning, icon::HOURGLASS, |ui| {
                ui.label(RichText::new(msg).color(t.text));
            });
        }
    }

    /// While connecting or connected: address, traffic and routes.
    fn connection_details(&mut self, ui: &mut Ui) {
        let t = theme::tokens(ui);
        if let Some(since) = self.since {
            let gap = 12.0;
            // a card's width plus its padding and border fill its share of the row
            let width = |per_row: usize| (ui.available_width() - (per_row - 1) as f32 * gap) / per_row as f32 - 2.0 * 14.0 - 2.0;
            // four in a row while the widest address and its copy button fit, else two rows of two
            let per_row = if width(4) >= STAT_MIN { 4 } else { 2 };
            let width = width(per_row);
            let ip = self.info.ip.map_or_else(|| "—".to_string(), |ip| ip.to_string());
            let (rx, tx) = (human(self.stats.0), human(self.stats.1));
            let since = duration(since.elapsed().as_secs());
            let value = |ui: &mut Ui, v: &str, template: &str| _ = theme::ticking(ui, v, template, 17.0);
            for row in ["IP Address", "Connected For", "Bytes Received", "Bytes Sent"].chunks(per_row) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = gap;
                    for label in row {
                        theme::stat(ui, label, width, |ui| match *label {
                            "IP Address" => {
                                ui.label(RichText::new(&ip).monospace().size(16.0).color(t.text));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    theme::copy_button(ui, egui::Id::new("copy-ip"), || ip.clone(), "Copy IP Address", None);
                                });
                            }
                            "Connected For" => value(ui, &since, "00:00:00"),
                            "Bytes Received" => value(ui, &rx, "0000.0 MB"),
                            _ => value(ui, &tx, "0000.0 MB"),
                        });
                    }
                });
            }
        }
        let p = &self.cfg.profiles[self.profile_connected];
        let mut rows = vec![("Remote Gateway", gateway_text(p))];
        if !self.info.username.is_empty() {
            rows.push(("Username", self.info.username.clone()));
        }
        if self.since.is_none()
            && let Some(ip) = self.info.ip
        {
            rows.push(("IP Address", ip.to_string()));
        }
        if !self.info.routes.is_empty() {
            let routes = if self.info.full_tunnel {
                "all traffic".to_string()
            } else {
                self.info.routes.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            };
            rows.push(("Routes", routes));
        }
        rows.push(("Interface", p.network.ifname.to_string()));
        theme::card(ui, |ui| {
            theme::card_title(ui, "Details", None);
            ui.spacing_mut().interact_size.y = 0.0;
            egui::Grid::new("details").num_columns(2).spacing([28.0, 10.0]).min_col_width(120.0).show(ui, |ui| {
                for (k, v) in rows {
                    ui.label(RichText::new(k).color(t.weak));
                    ui.add(egui::Label::new(RichText::new(v).color(t.text)).selectable(true).wrap());
                    ui.end_row();
                }
            });
        });
    }

    fn profile_editor(&mut self, ui: &mut Ui) {
        let i = self.cfg.selected;
        let (fix, scroll) = (self.fix_focus, std::mem::take(&mut self.fix_scroll));
        let (drafts, p) = (&mut self.drafts, &mut self.cfg.profiles[i]);
        connection_card(ui, drafts, p, self.keyring_warning.as_deref(), fix, scroll);
        sign_in_card(ui, drafts, p, fix, scroll);
        ui.horizontal(|ui| {
            ui.add_space(2.0);
            theme::eyebrow(ui, "Advanced");
        });
        advanced_cards(ui, drafts, p);
    }

    fn settings_page(&mut self, ui: &mut Ui) {
        if theme::quiet(ui, icon::ARROW_LEFT, "Back").clicked() {
            self.show_settings = false;
            self.settings_error = None;
        }
        ui.heading("Settings");
        if let Some(e) = &self.settings_error {
            theme::error_banner(ui, e, None, false);
        }
        theme::card(ui, |ui| {
            theme::card_title(ui, "This Installation", None);
            let key = (DraftOwner::App, Field::Uid);
            form::column_help(ui, WIDE, Field::Uid.label(), "Identifies this installation to the FortiGate, like the UID FortiClient generates at install.", |ui| {
                ui.horizontal_top(|ui| {
                    form::parsed(ui, &mut self.drafts, key.clone(), &mut self.cfg.uid, Look { width: Some(340.0), monospace: true, ..Look::default() }).on_hover_text(UID_HELP);
                    if theme::button(ui, true, icon::REFRESH, "Regenerate").clicked() {
                        self.ask_regenerate_uid();
                    }
                });
                ((), self.drafts.error(&key).map(str::to_owned))
            });
        });
        theme::card(ui, |ui| {
            theme::card_title(ui, "Logging", None);
            theme::toggle(ui, &mut self.cfg.verbose, "Verbose backend logging", Some("Adds IKE protocol detail, for troubleshooting. Keys are always redacted."));
        });
        theme::card(ui, |ui| {
            theme::card_title(ui, "Settings Folder", Some("Your connections are files in here, one per connection."));
            ui.horizontal(|ui| {
                let dir = Paths::from_env().config_dir;
                ui.add(egui::Label::new(RichText::new(dir.display().to_string()).monospace()).selectable(true));
                if theme::button(ui, true, icon::EXTERNAL_LINK, "Open Folder").clicked() {
                    match std::fs::create_dir_all(&dir) {
                        Ok(()) => self.open_from_settings(&dir, "the settings folder couldn't be opened"),
                        Err(e) => {
                            self.settings_error = Some(diag("error", "the settings folder couldn't be opened", &e.to_string(), &format!("open it yourself: {}", dir.display())));
                        }
                    }
                }
            });
        });
        ui.add_space(2.0);
        ui.label(theme::weak(ui, format!("Archway {}", env!("CARGO_PKG_VERSION"))));
    }
}

/// The width of one of two fields side by side.
fn half(ui: &Ui) -> f32 {
    ((ui.available_width() - FIELD_GAP) / 2.0).max(160.0)
}

/// A `form::column_help` whose field a connect error's fix button may point at: then it gets a focus ring and
/// FIX_HELP, and is scrolled to on the first frame (`scroll`).
fn fix_column(ui: &mut Ui, w: f32, label: &str, help: &str, pointed: bool, scroll: bool, add: impl FnOnce(&mut Ui) -> (egui::Response, Option<String>)) {
    form::column_help(ui, w, label, if pointed { FIX_HELP } else { help }, |ui| {
        let (r, warning) = add(ui);
        if pointed {
            if scroll {
                ui.scroll_to_rect(r.rect.expand(40.0), Some(Align::Center));
            }
            let ring = Stroke::new(2.0, theme::tokens(ui).focus);
            ui.painter().rect_stroke(r.rect.expand(1.0), ui.visuals().widgets.inactive.corner_radius, ring, egui::StrokeKind::Outside);
        }
        ((), warning)
    });
}

/// Gateway and PSK.
fn connection_card(ui: &mut Ui, drafts: &mut Drafts, p: &mut Profile, keyring_warning: Option<&str>, fix: Option<Fix>, scroll: bool) {
    let owner = DraftOwner::Profile(p.id.clone());
    let key = (owner.clone(), Field::Gateway);
    theme::card(ui, |ui| {
        theme::card_title(ui, "Connection", Some("Where to connect, and the key the gateway expects"));
        let w = half(ui);
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = FIELD_GAP;
            fix_column(ui, w, Field::Gateway.label(), "", fix == Some(Fix::Gateway) && p.gateway.is_none(), scroll, |ui| {
                let r = form::parsed_opt(ui, drafts, key.clone(), &mut p.gateway, Look { width: Some(w), ..Look::hint("vpn.example.com") });
                (r, drafts.error(&key).map(str::to_owned))
            });
            fix_column(ui, w, "Pre-shared Key", PSK_HELP, fix == Some(Fix::Psk) && p.psk.is_empty(), scroll, |ui| {
                (secret(ui, secret_id(&owner, "psk"), &mut p.psk, "Pre-shared Key", w), None)
            });
        });
        if let Some(w) = keyring_warning {
            ui.label(RichText::new(w).monospace().color(theme::tokens(ui).warning));
        }
    });
}

/// SSO, or username and password.
fn sign_in_card(ui: &mut Ui, drafts: &mut Drafts, p: &mut Profile, fix: Option<Fix>, scroll: bool) {
    let owner = DraftOwner::Profile(p.id.clone());
    let key = |f: Field| (owner.clone(), f);
    theme::card(ui, |ui| {
        theme::card_title(ui, "Sign-in", Some("How you log in to the VPN"));
        theme::toggle(ui, &mut p.sso.enabled, "Enable Single Sign On (SSO) for VPN Tunnel", Some("Log in on your organisation's web page."));
        ui.add_space(4.0);
        if p.sso.enabled {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = FIELD_GAP;
                form::parsed_field(ui, 220.0, drafts, key(Field::SsoPort), &mut p.sso.port, Look { help: "The FortiGate's auth-ike-saml-port.", width: Some(220.0), ..Look::PORT });
                form::column(ui, 220.0, "Login Timeout (s)", |ui| (ranged(ui, &mut p.sso.timeout, LoginTimeout::RANGE, "Login Timeout"), None));
            });
            ui.checkbox(&mut p.sso.open_browser, "Open the login page in the browser automatically");
            ui.checkbox(&mut p.sso.verify_cert, "Verify the server certificate on the SSO port");
            if !p.sso.verify_cert {
                let warning = "Without verification, anyone between you and the FortiGate can send you to a fake login page. Only turn this off if the FortiGate's certificate can't be verified.";
                ui.add(egui::Label::new(RichText::new(warning).color(theme::tokens(ui).warning)).wrap());
            }
        } else {
            ui.label(theme::caption(ui, "User Authentication"));
            ui.radio_value(&mut p.auth.mode, UserAuth::Eap, "Username and password (EAP)");
            ui.radio_value(&mut p.auth.mode, UserAuth::None, "None (pre-shared key only)");
            if p.auth.mode == UserAuth::Eap {
                ui.add_space(4.0);
                let w = half(ui);
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = FIELD_GAP;
                    let credentials = fix == Some(Fix::Credentials);
                    fix_column(ui, w, Field::Username.label(), "", credentials && p.auth.username.is_none(), scroll, |ui| {
                        let r = form::parsed_opt(ui, drafts, key(Field::Username), &mut p.auth.username, Look { width: Some(w), ..Look::default() });
                        (r, drafts.error(&key(Field::Username)).map(str::to_owned))
                    });
                    let pointed = credentials && p.auth.username.is_some() && p.auth.password.is_empty();
                    fix_column(ui, w, "Password", "", pointed, scroll, |ui| (secret(ui, secret_id(&owner, "password"), &mut p.auth.password, "Password", w), None));
                });
                ui.checkbox(&mut p.auth.save_password, "Save password").on_hover_text("Unchecked: the password is only kept in memory until the app is closed");
            }
        }
    });
}

/// VPN settings, Phase 1, Phase 2 and Network, folded.
fn advanced_cards(ui: &mut Ui, drafts: &mut Drafts, p: &mut Profile) {
    let owner = DraftOwner::Profile(p.id.clone());
    let key = |f: Field| (owner.clone(), f);
    let has = |drafts: &Drafts, fields: &[Field]| fields.iter().any(|f| drafts.error(&key(*f)).is_some());
    let vpn_marked = has(drafts, &[Field::IkePort]);
    theme::fold_card(ui, "VPN Settings", &format!("IKEv2 · UDP port {}", p.ike.port), vpn_marked, |ui| {
        ui.label(theme::weak(ui, "IKE version 2, addresses by Mode Config"));
        form::parsed_field(ui, 220.0, drafts, key(Field::IkePort), &mut p.ike.port, Look { width: Some(220.0), ..Look::PORT });
    });

    let dh = p.ike.dh_groups.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    let p1 = format!("{} · DH {}", proposals_summary(&p.ike.proposals), if dh.is_empty() { "none" } else { &dh });
    let p1_marked = p.ike.proposals.is_empty() || p.ike.dh_groups.is_empty() || has(drafts, &[Field::LocalId]);
    theme::fold_card(ui, "Phase 1", &p1, p1_marked, |ui| {
        proposal_rows(ui, "p1", &mut p.ike.proposals);
        form::warning_slot(ui, p.ike.proposals.is_empty().then_some(config::NO_P1_PROPOSAL));
        ui.label(theme::caption(ui, "DH Group"));
        dh_checkboxes(ui, &mut p.ike.dh_groups);
        form::warning_slot(ui, p.ike.dh_groups.is_empty().then_some(config::NO_DH_GROUP));
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = FIELD_GAP;
            form::parsed_opt_field(ui, 300.0, drafts, key(Field::LocalId), &mut p.ike.local_id, Look { width: Some(300.0), ..Look::hint("optional (default: local IP)") });
            form::column(ui, 180.0, "NAT-T Keepalive (s)", |ui| (ranged(ui, &mut p.ike.natt_keepalive, Keepalive::RANGE, "NAT-T Keepalive"), None));
        });
    });

    theme::fold_card(ui, "Phase 2", &proposals_summary(&p.esp.proposals), p.esp.proposals.is_empty(), |ui| {
        proposal_rows(ui, "p2", &mut p.esp.proposals);
        form::warning_slot(ui, p.esp.proposals.is_empty().then_some(config::NO_P2_PROPOSAL));
    });

    let routing = match p.network.route_mode {
        RouteMode::Gateway => "routes from the FortiGate",
        RouteMode::Full => "all traffic",
        RouteMode::Custom => "only listed networks",
    };
    let custom = p.network.route_mode == RouteMode::Custom;
    let net_marked = has(drafts, &[Field::IfName]) || (custom && (p.network.custom_routes.is_empty() || has(drafts, &[Field::CustomRoutes])));
    theme::fold_card(ui, "Network", &format!("{routing} · {}", p.network.ifname), net_marked, |ui| {
        ui.label(theme::caption(ui, "Routing"));
        ui.radio_value(&mut p.network.route_mode, RouteMode::Gateway, "As pushed by the FortiGate");
        ui.radio_value(&mut p.network.route_mode, RouteMode::Full, "All traffic through the VPN");
        ui.radio_value(&mut p.network.route_mode, RouteMode::Custom, "Only these networks:");
        if p.network.route_mode == RouteMode::Custom {
            ui.horizontal(|ui| {
                ui.add_space(26.0);
                ui.vertical(|ui| {
                    let look = Look { multiline: true, width: Some(320.0), monospace: true, ..Look::hint("10.0.0.0/8\n192.168.10.0/24") };
                    form::text_field(ui, drafts, key(Field::CustomRoutes), &mut p.network.custom_routes, look, |v| v.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n"), Ipv4Net::parse_list);
                    // the text's own error first, else "enter at least one", in the one slot
                    let empty = p.network.custom_routes.is_empty().then_some(config::NO_ROUTES);
                    form::warning_slot(ui, drafts.error(&key(Field::CustomRoutes)).or(empty));
                });
            });
        }
        ui.checkbox(&mut p.network.set_dns, "Use DNS servers from the VPN (systemd-resolved)");
        ui.checkbox(&mut p.network.block_ipv6, "Block IPv6 while all traffic goes through the VPN");
        ui.add_space(4.0);
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = FIELD_GAP;
            form::parsed_field(ui, 220.0, drafts, key(Field::IfName), &mut p.network.ifname, Look { width: Some(220.0), monospace: true, ..Look::default() });
            form::column(ui, 160.0, "MTU", |ui| (ranged(ui, &mut p.network.mtu, Mtu::RANGE, "MTU"), None));
        });
    });
}

/// Ask `title`; Some(true) for the confirm button, Some(false) for Cancel, Escape or a click outside, None while open.
fn confirm(ctx: &egui::Context, id: &str, title: &str, body: &str, (tone, label): (Tone, &str)) -> Option<bool> {
    let mut answer = None;
    let modal = egui::Modal::new(egui::Id::new(id)).show(ctx, |ui| {
        ui.set_max_width(400.0);
        ui.spacing_mut().item_spacing.y = 10.0;
        ui.label(theme::title(ui, title, 17.0));
        ui.label(RichText::new(body).color(theme::tokens(ui).secondary));
        ui.add_space(6.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if theme::solid(ui, true, tone, "", label).clicked() {
                answer = Some(true);
            }
            if theme::button(ui, true, "", "Cancel").clicked() {
                answer = Some(false);
            }
        });
    });
    answer.or(modal.should_close().then_some(false))
}

/// The id of the password field for `what` ("psk", "password") of `owner`, so a fix button can focus it.
fn secret_id(owner: &DraftOwner, what: &str) -> egui::Id {
    egui::Id::new(("form-secret", owner, what))
}

/// A password field with no draft: any text is valid.
fn secret(ui: &mut Ui, id: egui::Id, value: &mut String, label: &str, width: f32) -> egui::Response {
    let edit = egui::TextEdit::singleline(value).id(id).password(true).margin(Margin::symmetric(10, 10)).desired_width(width);
    theme::labelled(ui.add(edit), label)
}

/// The DH groups this client supports as checkboxes, kept sorted, after a few it doesn't (disabled).
fn dh_checkboxes(ui: &mut Ui, groups: &mut Vec<DhGroup>) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 16.0;
        for g in DH_UNSUPPORTED.iter().take(DH_UNSUPPORTED_SHOWN) {
            ui.add_enabled(false, egui::Checkbox::new(&mut false, g.to_string())).on_disabled_hover_text("not supported by this client");
        }
        for g in DhGroup::ALL {
            let mut on = groups.contains(&g);
            if ui.checkbox(&mut on, g.to_string()).changed() {
                if on {
                    groups.push(g);
                    groups.sort_by_key(|g| u16::from(*g));
                } else {
                    groups.retain(|x| *x != g);
                }
            }
        }
    });
}

fn duration(s: u64) -> String {
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

/// Bytes in the largest unit that keeps the number at least 1.
fn human(b: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}

fn proposals_summary(props: &[Proposal]) -> String {
    match props {
        [] => "no proposal".into(),
        [one] => one.to_string(),
        [first, rest @ ..] => format!("{first} +{}", rest.len()),
    }
}

fn proposal_rows(ui: &mut Ui, id: &str, props: &mut Vec<Proposal>) {
    let mut remove = None;
    egui::Grid::new(id).num_columns(3).spacing([12.0, 6.0]).min_col_width(150.0).show(ui, |ui| {
        ui.label(theme::caption(ui, "Encryption"));
        ui.label(theme::caption(ui, "Authentication"));
        ui.end_row();
        for (i, p) in props.iter_mut().enumerate() {
            let enc = egui::ComboBox::from_id_salt((id, i, "enc")).width(150.0).selected_text(p.enc.to_string()).show_ui(ui, |ui| {
                for e in Encryption::ALL {
                    ui.selectable_value(&mut p.enc, e, e.to_string());
                }
            });
            theme::labelled(enc.response, &format!("Encryption, proposal {}", i + 1));
            let hash = egui::ComboBox::from_id_salt((id, i, "hash")).width(150.0).selected_text(p.hash.to_string()).show_ui(ui, |ui| {
                for h in Hash::ALL {
                    ui.selectable_value(&mut p.hash, h, h.to_string());
                }
            });
            theme::labelled(hash.response, &format!("Authentication, proposal {}", i + 1));
            if theme::small_icon_button(ui, true, icon::X, "Remove proposal", Color32::PLACEHOLDER).clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if let Some(i) = remove {
        props.remove(i);
    }
    if props.len() < MAX_PROPOSALS && theme::quiet(ui, icon::PLUS, "Add Proposal").clicked() {
        props.push(Proposal::default());
    }
}

/// DragValue for a range-limited setting: the widget's range keeps the value valid. `label` names it for screen
/// readers (the caption above it is a separate widget).
fn ranged<T: Copy + Into<u16> + TryFrom<u16>>(ui: &mut Ui, value: &mut T, range: std::ops::RangeInclusive<u16>, label: &str) {
    let mut v: u16 = (*value).into();
    theme::labelled(ui.add_sized([120.0, 38.0], egui::DragValue::new(&mut v).range(range)), label);
    if let Ok(t) = T::try_from(v) {
        *value = t;
    }
}
