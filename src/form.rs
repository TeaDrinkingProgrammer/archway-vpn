//! Editing typed settings as text. The value in `Profile`/`Config` is always valid. While the text the user typed for
//! a field differs from it, the text lives in `Drafts`. A draft that doesn't parse shows its error under the field,
//! keeps the last valid value, and makes the app refuse Save and Connect until it's fixed.

use crate::config::{Profile, RouteMode, UserAuth};
use eframe::egui::{self, RichText};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

/// Whose field a draft belongs to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DraftOwner {
    /// a profile, by its id
    Profile(String),
    /// the app settings (the client UID)
    App,
}

/// The text fields that hold typed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field {
    Name,
    Description,
    Gateway,
    Username,
    SsoPort,
    IkePort,
    LocalId,
    CustomRoutes,
    IfName,
    Uid,
}

impl Field {
    /// The field's label in the editor, for messages that name it.
    pub fn label(self) -> &'static str {
        match self {
            Field::Name => "Connection Name",
            Field::Description => "Description",
            Field::Gateway => "Remote Gateway",
            Field::Username => "Username",
            Field::SsoPort => "SSO Port",
            Field::IkePort => "IKE UDP Port",
            Field::LocalId => "Local ID",
            Field::CustomRoutes => "Custom routes",
            Field::IfName => "Interface Name",
            Field::Uid => "Client UID",
        }
    }

    /// Whether profile `p` uses this field in its current mode. Text that doesn't parse in a field it doesn't use (the
    /// username while SSO is on, custom routes outside Custom routing) blocks nothing; it's kept, and counts again once
    /// the mode uses the field.
    pub fn in_use(self, p: &Profile) -> bool {
        let Some(f) = p.fortigate() else {
            return !matches!(self, Field::Username | Field::SsoPort | Field::CustomRoutes);
        };
        match self {
            Field::Username => !f.sso.enabled && f.auth.mode == UserAuth::Eap,
            Field::SsoPort => f.sso.enabled,
            Field::CustomRoutes => f.network.route_mode == RouteMode::Custom,
            _ => true,
        }
    }
}

pub type DraftKey = (DraftOwner, Field);

#[derive(Clone, Debug, PartialEq)]
struct Draft {
    text: String,
    /// why `text` doesn't parse; None: it parsed and the value was updated
    error: Option<String>,
}

#[derive(Debug, Default)]
pub struct Drafts {
    map: BTreeMap<DraftKey, Draft>,
}

impl Drafts {
    /// The user changed the field's text to `text`: update `value` if it parses, remember the text either way.
    pub fn edit_with<V>(
        &mut self,
        key: DraftKey,
        text: String,
        value: &mut V,
        parse: impl FnOnce(&str) -> Result<V, String>,
    ) {
        let error = parse(&text).map(|v| *value = v).err();
        self.map.insert(key, Draft { text, error });
    }

    /// `edit_with` for a type that parses from text. The editor goes through `text_field`; tests type with this.
    #[cfg(test)]
    pub fn edit<V: FromStr<Err = String>>(&mut self, key: DraftKey, text: String, value: &mut V) {
        self.edit_with(key, text, value, |s| s.parse())
    }

    /// Like `edit`; empty (or blank) text means None.
    #[cfg(test)]
    pub fn edit_opt<V: FromStr<Err = String>>(
        &mut self,
        key: DraftKey,
        text: String,
        value: &mut Option<V>,
    ) {
        self.edit_with(key, text, value, parse_opt)
    }

    /// Focus left the field: a draft that parsed has done its job (the value holds it), so the field shows the value
    /// again. An invalid draft stays.
    pub fn settle(&mut self, key: &DraftKey) {
        if self.map.get(key).is_some_and(|d| d.error.is_none()) {
            self.map.remove(key);
        }
    }

    pub fn text(&self, key: &DraftKey) -> Option<&str> {
        self.map.get(key).map(|d| d.text.as_str())
    }

    pub fn error(&self, key: &DraftKey) -> Option<&str> {
        self.map.get(key)?.error.as_deref()
    }

    /// Every draft that doesn't parse, with its error.
    pub fn errors(&self) -> impl Iterator<Item = (&DraftKey, &str)> {
        self.map
            .iter()
            .filter_map(|(k, d)| Some((k, d.error.as_deref()?)))
    }

    #[cfg(test)]
    pub fn has_errors(&self) -> bool {
        self.errors().next().is_some()
    }

    /// The value was set another way (Browse…, Regenerate): forget the typed text.
    pub fn remove(&mut self, key: &DraftKey) {
        self.map.remove(key);
    }

    /// The profile was deleted.
    pub fn remove_owner(&mut self, owner: &DraftOwner) {
        self.map.retain(|(o, _), _| o != owner);
    }
}

fn parse_opt<V: FromStr<Err = String>>(s: &str) -> Result<Option<V>, String> {
    if s.trim().is_empty() {
        Ok(None)
    } else {
        s.parse().map(Some)
    }
}

/// How a text field looks.
#[derive(Clone, Copy, Default)]
pub struct Look {
    pub hint: &'static str,
    /// shown in the slot under the field while it has no warning
    pub help: &'static str,
    pub width: Option<f32>,
    pub multiline: bool,
    pub monospace: bool,
    /// frameless, in text of this size: the status card's name (semibold) and description
    pub inline: Option<f32>,
}

impl Look {
    pub const PORT: Look = Look {
        hint: "",
        help: "",
        width: Some(120.0),
        multiline: false,
        monospace: true,
        inline: None,
    };

    pub const fn hint(hint: &'static str) -> Look {
        Look {
            hint,
            help: "",
            width: None,
            multiline: false,
            monospace: false,
            inline: None,
        }
    }
}

/// A column as wide as there is room for.
pub const WIDE: f32 = f32::INFINITY;

/// A column of a fixed `width` (so a field next to it doesn't move): `label` above, what `add` draws, and the
/// warning `add` returns in the slot below.
pub fn column<R>(
    ui: &mut egui::Ui,
    width: f32,
    label: &str,
    add: impl FnOnce(&mut egui::Ui) -> (R, Option<String>),
) -> R {
    column_help(ui, width, label, "", add)
}

/// `column` with `help` in the slot while there is no warning.
pub fn column_help<R>(
    ui: &mut egui::Ui,
    width: f32,
    label: &str,
    help: &str,
    add: impl FnOnce(&mut egui::Ui) -> (R, Option<String>),
) -> R {
    ui.vertical(|ui| {
        ui.set_width(width.min(ui.available_width()));
        ui.spacing_mut().item_spacing.y = 4.0;
        ui.label(crate::theme::caption(ui, label));
        let (r, warning) = add(ui);
        slot(ui, warning.as_deref(), help);
        r
    })
    .inner
}

/// One line that is always there, so a warning appearing doesn't move what's below it: "⚠ {msg}" in red, cut to the
/// line if it's longer (all of it on hover), or `help` in the help colour, or nothing. The real ⚠ character, not an
/// icon-font glyph, so screen readers say it.
pub fn slot(ui: &mut egui::Ui, warning: Option<&str>, help: &str) {
    let size = egui::vec2(ui.available_width(), 18.0);
    ui.allocate_ui_with_layout(
        size,
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_min_size(size);
            let t = crate::theme::tokens(ui);
            let (text, color) = match warning {
                Some(m) => (format!("⚠ {m}"), t.danger),
                None => (help.to_owned(), t.weak),
            };
            if !text.is_empty() {
                ui.add(
                    egui::Label::new(RichText::new(&text).size(crate::theme::SMALL).color(color))
                        .truncate(),
                )
                .on_hover_text(text);
            }
        },
    );
}

/// `slot` without help.
pub fn warning_slot(ui: &mut egui::Ui, msg: Option<&str>) {
    slot(ui, msg, "");
}

/// The id of the text field for `key`, from the field, not from the layout.
pub fn field_id(key: &DraftKey) -> egui::Id {
    egui::Id::unique(("form-field", key))
}

/// Runs `add`, which adds the text field `id`. A right-click inside the field's selection keeps the selection, as in
/// other apps, so the menu acts on it; a right-click elsewhere moves the cursor there (egui moves it on any button).
pub fn keep_selection_on_right_click(
    ui: &mut egui::Ui,
    id: egui::Id,
    add: impl FnOnce(&mut egui::Ui) -> egui::Response,
) -> egui::Response {
    let ctx = ui.ctx().clone();
    let pos = ctx.input(|i| {
        let p = &i.pointer;
        (p.secondary_pressed() || p.secondary_down() || p.secondary_released())
            .then(|| p.interact_pos())
            .flatten()
    });
    let on_field = pos.is_some_and(|pos| {
        ctx.read_response(id)
            .is_some_and(|r| r.interact_rect.contains(pos))
    });
    let before = on_field
        .then(|| egui::TextEdit::load_state(&ctx, id))
        .flatten()
        .filter(|s| s.cursor.char_range().is_some_and(|c| !c.is_empty()));
    let r = add(ui);
    if let Some(before) = before {
        let clicked = egui::TextEdit::load_state(&ctx, id)
            .and_then(|s| s.cursor.char_range())
            .map(|c| c.primary.index);
        let selected = before.cursor.char_range().map(|c| c.as_sorted_char_range());
        if let (Some(at), Some(sel)) = (clicked, selected)
            && sel.start <= at
            && at <= sel.end
        {
            before.store(&ctx, id);
        }
    }
    r
}

/// The right-click menu of text field `r` showing `text`: Cut, Copy, Paste and Select All, or for a password only
/// Paste and Select All. The field does the editing: an item gives it back its focus and the selection the menu was
/// opened on, then asks the window for the same event as Ctrl+X/C/V. egui 0.37 drops the selection when another widget
/// is clicked: https://github.com/emilk/egui/issues/8763
pub fn edit_menu(r: &egui::Response, text: &str, password: bool) {
    let ctx = r.ctx.clone();
    let id = r.id;
    let opened_on = id.with("menu-selection");
    // typing while the menu is open changes the selection, and the undo history
    if r.secondary_clicked() || r.changed() {
        let s = egui::TextEdit::load_state(&ctx, id).unwrap_or_default();
        ctx.data_mut(|d| d.insert_temp(opened_on, s));
    }
    r.context_menu(|ui| {
        let state: egui::text_edit::TextEditState =
            ctx.data(|d| d.get_temp(opened_on)).unwrap_or_default();
        let selected = state.cursor.char_range().is_some_and(|c| !c.is_empty());
        let mut command = None;
        let mut item = |ui: &mut egui::Ui, label: &str, enabled: bool, c| {
            if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                command = Some(c);
            }
        };
        if !password {
            item(ui, "Cut", selected, egui::ViewportCommand::RequestCut);
            item(ui, "Copy", selected, egui::ViewportCommand::RequestCopy);
        }
        item(ui, "Paste", true, egui::ViewportCommand::RequestPaste);
        let select_all = ui.button("Select All").clicked();
        if command.is_some() || select_all {
            let mut s = state;
            if select_all {
                s.cursor
                    .set_char_range(Some(egui::text::CCursorRange::select_all_str(text)));
            }
            s.store(&ctx, id);
            ctx.memory_mut(|m| m.request_focus(id));
            if let Some(c) = command {
                ctx.send_viewport_cmd(c);
            }
            ui.close();
        }
    });
}

/// A text field for `value`: shows the draft for `key` if there is one, else `show(value)`. Edits go through `parse`;
/// while the text doesn't parse the field has a warning outline (the message is the caller's to show).
pub fn text_field<V>(
    ui: &mut egui::Ui,
    drafts: &mut Drafts,
    key: DraftKey,
    value: &mut V,
    look: Look,
    show: impl FnOnce(&V) -> String,
    parse: impl FnOnce(&str) -> Result<V, String>,
) -> egui::Response {
    let mut text = drafts.text(&key).map_or_else(|| show(value), str::to_owned);
    let edit = if look.multiline {
        egui::TextEdit::multiline(&mut text).desired_rows(3)
    } else {
        egui::TextEdit::singleline(&mut text)
    };
    // an id from the field, not from the layout: a warning or problem line appearing elsewhere mustn't make this a
    // new widget, which would take the focus away mid-typing
    let mut edit = edit
        .id(field_id(&key))
        .hint_text(look.hint)
        .margin(egui::Margin::symmetric(10, 10));
    if let Some(w) = look.width {
        edit = edit.desired_width(w);
    }
    if look.monospace {
        edit = edit.font(egui::TextStyle::Monospace);
    }
    let t = crate::theme::tokens(ui);
    if let Some(size) = look.inline {
        let (font, color) = if size >= 20.0 {
            (crate::theme::strong_font(ui.ctx(), size), t.text)
        } else {
            (egui::FontId::proportional(size), t.weak)
        };
        edit = edit
            .frame(egui::Frame::NONE)
            .margin(egui::Margin::ZERO)
            .font(font)
            .text_color(color);
    }
    let r = keep_selection_on_right_click(ui, field_id(&key), |ui| ui.add(edit));
    edit_menu(&r, &text, false);
    let r = crate::theme::labelled(r, key.1.label());
    if look.inline.is_some() {
        // a line under it says it can be edited: dashed on hover, solid while editing
        let y = r.rect.bottom() + 1.0;
        if r.has_focus() {
            ui.painter()
                .hline(r.rect.x_range(), y, egui::Stroke::new(2.0, t.focus));
        } else if r.hovered() {
            let line = [egui::pos2(r.rect.left(), y), egui::pos2(r.rect.right(), y)];
            ui.painter().extend(egui::Shape::dashed_line(
                &line,
                egui::Stroke::new(1.0, t.weak),
                4.0,
                3.0,
            ));
        }
    } else if drafts.error(&key).is_some() {
        ui.painter().rect_stroke(
            r.rect,
            ui.visuals().widgets.inactive.corner_radius,
            egui::Stroke::new(1.0, t.danger_line),
            egui::StrokeKind::Inside,
        );
    }
    if r.changed() {
        drafts.edit_with(key.clone(), text, value, parse);
    }
    if !r.has_focus() {
        drafts.settle(&key);
    }
    r
}

/// `text_field` for a type that parses from its own `Display` text.
pub fn parsed<V: FromStr<Err = String> + Display>(
    ui: &mut egui::Ui,
    drafts: &mut Drafts,
    key: DraftKey,
    value: &mut V,
    look: Look,
) -> egui::Response {
    text_field(
        ui,
        drafts,
        key,
        value,
        look,
        |v| v.to_string(),
        |s| s.parse(),
    )
}

/// `parsed` for an optional value: an empty field is None.
pub fn parsed_opt<V: FromStr<Err = String> + Display>(
    ui: &mut egui::Ui,
    drafts: &mut Drafts,
    key: DraftKey,
    value: &mut Option<V>,
    look: Look,
) -> egui::Response {
    text_field(
        ui,
        drafts,
        key,
        value,
        look,
        |v| v.as_ref().map(ToString::to_string).unwrap_or_default(),
        parse_opt,
    )
}

/// `parsed` in a `column` captioned with the field's label, its error in the slot below.
pub fn parsed_field<V: FromStr<Err = String> + Display>(
    ui: &mut egui::Ui,
    width: f32,
    drafts: &mut Drafts,
    key: DraftKey,
    value: &mut V,
    look: Look,
) -> egui::Response {
    column_help(ui, width, key.1.label(), look.help, |ui| {
        (
            parsed(ui, drafts, key.clone(), value, look),
            drafts.error(&key).map(str::to_owned),
        )
    })
}

/// `parsed_opt` in a `column`, like `parsed_field`.
pub fn parsed_opt_field<V: FromStr<Err = String> + Display>(
    ui: &mut egui::Ui,
    width: f32,
    drafts: &mut Drafts,
    key: DraftKey,
    value: &mut Option<V>,
    look: Look,
) -> egui::Response {
    column_help(ui, width, key.1.label(), look.help, |ui| {
        (
            parsed_opt(ui, drafts, key.clone(), value, look),
            drafts.error(&key).map(str::to_owned),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Port;

    fn key(f: Field) -> DraftKey {
        (DraftOwner::Profile("p1".into()), f)
    }

    #[test]
    fn invalid_text_keeps_the_value_and_reports_why() {
        let mut d = Drafts::default();
        let mut port = Port::new(443).unwrap();
        d.edit(key(Field::IkePort), "0".into(), &mut port);
        assert_eq!(port.get(), 443);
        assert_eq!(
            d.error(&key(Field::IkePort)),
            Some("Port must be 1 to 65535.")
        );
        assert_eq!(d.text(&key(Field::IkePort)), Some("0"));
        assert!(d.has_errors());
        d.settle(&key(Field::IkePort));
        assert_eq!(
            d.text(&key(Field::IkePort)),
            Some("0"),
            "an invalid draft stays after focus leaves"
        );
    }

    #[test]
    fn valid_text_updates_the_value_and_settles_away() {
        let mut d = Drafts::default();
        let mut port = Port::new(443).unwrap();
        d.edit(key(Field::IkePort), " 8443".into(), &mut port);
        assert_eq!(port.get(), 8443);
        assert_eq!(
            d.text(&key(Field::IkePort)),
            Some(" 8443"),
            "kept while the field has focus"
        );
        assert!(!d.has_errors());
        d.settle(&key(Field::IkePort));
        assert_eq!(d.text(&key(Field::IkePort)), None);
    }

    #[test]
    fn empty_optional_text_is_none() {
        let mut d = Drafts::default();
        let mut gw: Option<crate::net::Host> = Some("vpn.example.com".parse().unwrap());
        d.edit_opt(key(Field::Gateway), "  ".into(), &mut gw);
        assert_eq!(gw, None);
        assert!(!d.has_errors());
        d.edit_opt(key(Field::Gateway), "a b".into(), &mut gw);
        assert_eq!(gw, None, "still the last valid value");
        assert!(
            d.error(&key(Field::Gateway))
                .unwrap()
                .starts_with("Expected a host name")
        );
    }

    #[test]
    fn errors_list_every_invalid_draft_and_owners_can_be_dropped() {
        let mut d = Drafts::default();
        let (mut a, mut b) = (Port::new(1).unwrap(), Port::new(1).unwrap());
        d.edit(key(Field::IkePort), "x".into(), &mut a);
        d.edit((DraftOwner::App, Field::SsoPort), "y".into(), &mut b);
        assert_eq!(d.errors().count(), 2);
        d.remove_owner(&DraftOwner::Profile("p1".into()));
        assert_eq!(
            d.errors().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
            [(DraftOwner::App, Field::SsoPort)]
        );
        d.remove(&(DraftOwner::App, Field::SsoPort));
        assert!(!d.has_errors());
    }

    // ---- the egui widget ----

    /// Focus the port field, send `events`, then move focus away. Returns the port, the drafts and the visible texts.
    fn edit_port(start: u16, events: Vec<egui::Event>) -> (u16, Drafts, Vec<String>) {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        // the app's fonts, as egui brings none of its own (no "default_fonts")
        for _ in 0..2 {
            ctx.run_ui(Default::default(), |ui| crate::theme::install(ui.ctx()))
                .drop_without_applying_deltas();
        }
        let mut port = Port::new(start).unwrap();
        let mut drafts = Drafts::default();
        let mut texts = vec![];
        let mut run =
            |port: &mut Port, drafts: &mut Drafts, events: Vec<egui::Event>, focus: bool| {
                let mut out = ctx.run_ui(
                    egui::RawInput {
                        events,
                        ..Default::default()
                    },
                    |ui| {
                        let r =
                            parsed_field(ui, WIDE, drafts, key(Field::IkePort), port, Look::PORT);
                        if focus {
                            r.request_focus();
                        } else {
                            r.surrender_focus();
                        }
                    },
                );
                if let Some(u) = out.platform_output.accesskit_update.take() {
                    texts = u
                        .nodes
                        .iter()
                        .filter_map(|(_, n)| n.label().or(n.value()).map(str::to_owned))
                        .collect();
                }
                out.drop_without_applying_deltas();
            };
        run(&mut port, &mut drafts, vec![], true);
        run(&mut port, &mut drafts, events, true);
        run(&mut port, &mut drafts, vec![], false);
        run(&mut port, &mut drafts, vec![], false);
        (port.get(), drafts, texts)
    }

    fn select_all() -> egui::Event {
        egui::Event::Key {
            key: egui::Key::A,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::COMMAND,
        }
    }

    #[test]
    fn port_field_takes_a_typed_port() {
        let (port, drafts, _) =
            edit_port(443, vec![select_all(), egui::Event::Text("8443".into())]);
        assert_eq!(port, 8443);
        assert!(
            drafts.text(&key(Field::IkePort)).is_none(),
            "settled once focus left"
        );
    }

    #[test]
    fn port_field_rejects_too_big_instead_of_clamping() {
        let (port, drafts, texts) = edit_port(443, vec![egui::Event::Text("8443".into())]); // appended: 4438443
        assert_eq!(port, 443);
        assert_eq!(
            drafts.text(&key(Field::IkePort)),
            Some("4438443"),
            "what the user typed is kept"
        );
        assert!(
            texts.iter().any(|t| t == "⚠ Port must be 1 to 65535."),
            "{texts:?}"
        );
    }

    #[test]
    fn fields_are_labelled_for_screen_readers() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut port = Port::new(443).unwrap();
        let mut drafts = Drafts::default();
        let mut out = ctx.run_ui(Default::default(), |ui| {
            parsed(ui, &mut drafts, key(Field::IkePort), &mut port, Look::PORT);
        });
        let nodes = out.platform_output.accesskit_update.take().unwrap().nodes;
        out.drop_without_applying_deltas();
        assert!(
            nodes
                .iter()
                .any(|(_, n)| n.role() == egui::accesskit::Role::TextInput
                    && n.label() == Some("IKE UDP Port"))
        );
    }

    // ---- the right-click menu ----

    /// A text field (a password field if `password`) in a test window, driven one frame at a time.
    struct Menu {
        ctx: egui::Context,
        text: String,
        password: bool,
        nodes: Vec<(egui::accesskit::NodeId, egui::accesskit::Node)>,
        commands: Vec<egui::ViewportCommand>,
        copied: Vec<String>,
    }

    const ID: &str = "menu-test-field";

    impl Menu {
        fn new(text: &str, password: bool) -> Self {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            for _ in 0..2 {
                ctx.run_ui(Default::default(), |ui| crate::theme::install(ui.ctx()))
                    .drop_without_applying_deltas();
            }
            let mut m = Menu {
                ctx,
                text: text.into(),
                password,
                nodes: vec![],
                commands: vec![],
                copied: vec![],
            };
            m.run(vec![]);
            m
        }

        fn id() -> egui::Id {
            egui::Id::unique(ID)
        }

        fn run(&mut self, events: Vec<egui::Event>) {
            let (text, password) = (&mut self.text, self.password);
            let mut out = self.ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    keep_selection_on_right_click(ui, Self::id(), |ui| {
                        let r = ui.add(
                            egui::TextEdit::singleline(text)
                                .id(Self::id())
                                .password(password),
                        );
                        edit_menu(&r, text.as_str(), password);
                        r
                    });
                },
            );
            self.nodes = out
                .platform_output
                .accesskit_update
                .take()
                .map(|u| u.nodes)
                .unwrap_or_default();
            self.commands = out
                .viewport_output
                .values()
                .flat_map(|v| v.commands.clone())
                .collect();
            self.copied = out
                .platform_output
                .commands
                .iter()
                .filter_map(|c| match c {
                    egui::OutputCommand::CopyText(t) => Some(t.clone()),
                    _ => None,
                })
                .collect();
            out.drop_without_applying_deltas();
        }

        fn select(&mut self, from: usize, to: usize) {
            let mut s = egui::TextEdit::load_state(&self.ctx, Self::id()).unwrap_or_default();
            s.cursor.set_char_range(Some(egui::text::CCursorRange::two(
                egui::text::CCursor::new(from),
                egui::text::CCursor::new(to),
            )));
            s.store(&self.ctx, Self::id());
            self.ctx.memory_mut(|m| m.request_focus(Self::id()));
            self.run(vec![]);
        }

        fn selection(&self) -> Option<std::ops::Range<usize>> {
            egui::TextEdit::load_state(&self.ctx, Self::id())
                .and_then(|s| s.cursor.char_range())
                .map(|r| {
                    let [a, b] = r.sorted_cursors();
                    a.index.0..b.index.0
                })
        }

        fn right_click(&mut self) {
            let pos = self.ctx.read_response(Self::id()).unwrap().rect.center();
            let button = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Secondary,
                pressed,
                modifiers: Default::default(),
            };
            self.run(vec![egui::Event::PointerMoved(pos), button(true)]);
            self.run(vec![button(false)]);
            self.run(vec![]);
        }

        fn item(&self, label: &str) -> Option<&egui::accesskit::Node> {
            self.nodes
                .iter()
                .map(|(_, n)| n)
                .find(|n| n.label() == Some(label))
        }

        /// Click menu item `label` with the mouse, as only that drops the selection:
        /// https://github.com/emilk/egui/issues/8763
        fn click(&mut self, label: &str) {
            let b = self.item(label).and_then(|n| n.bounds()).expect(label);
            let pos = egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32);
            let button = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            };
            self.run(vec![egui::Event::PointerMoved(pos), button(true)]);
            self.run(vec![button(false)]);
        }

        fn focused(&self) -> bool {
            self.ctx.memory(|m| m.has_focus(Self::id()))
        }
    }

    #[test]
    fn right_click_keeps_the_selection_and_offers_cut_copy_paste() {
        let mut m = Menu::new("vpn.example.com", false);
        // the click lands past the end of the text, inside the selection
        m.select(4, 15);
        m.right_click();
        assert_eq!(
            m.selection(),
            Some(4..15),
            "the right-click didn't move the cursor"
        );
        for item in ["Cut", "Copy", "Paste", "Select All"] {
            assert!(m.item(item).is_some_and(|n| !n.is_disabled()), "{item}");
        }
        m.click("Copy");
        assert!(m.commands.contains(&egui::ViewportCommand::RequestCopy));
        assert!(m.focused(), "the field has the focus back for the copy");
        assert_eq!(m.selection(), Some(4..15));
        // what the window sends back for RequestCopy
        m.run(vec![egui::Event::Copy]);
        assert_eq!(m.copied, ["example.com"]);
        assert!(m.item("Cut").is_none(), "the menu closed");
    }

    #[test]
    fn right_click_outside_the_selection_moves_the_cursor() {
        let mut m = Menu::new("vpn.example.com", false);
        m.select(4, 11);
        m.right_click();
        assert_eq!(m.selection(), Some(15..15));
        assert!(m.item("Copy").unwrap().is_disabled());
    }

    #[test]
    fn cut_and_paste_go_to_the_field() {
        let mut m = Menu::new("abc", false);
        m.select(0, 3);
        m.right_click();
        m.click("Cut");
        assert!(m.commands.contains(&egui::ViewportCommand::RequestCut));
        // what the window sends back for RequestCut
        m.run(vec![egui::Event::Cut]);
        assert_eq!(m.text, "");
        m.right_click();
        m.click("Paste");
        assert!(m.commands.contains(&egui::ViewportCommand::RequestPaste));
        m.run(vec![egui::Event::Paste("xyz".into())]);
        assert_eq!(m.text, "xyz");
    }

    #[test]
    fn without_a_selection_only_paste_and_select_all_work() {
        let mut m = Menu::new("abc", false);
        m.right_click();
        assert!(m.item("Cut").unwrap().is_disabled());
        assert!(m.item("Copy").unwrap().is_disabled());
        assert!(!m.item("Paste").unwrap().is_disabled());
        m.click("Select All");
        assert_eq!(m.selection(), Some(0..3));
        assert!(m.focused());
    }

    #[test]
    fn typing_while_the_menu_is_open_updates_what_it_acts_on() {
        let mut m = Menu::new("abcdef", false);
        m.select(3, 6);
        m.right_click();
        // the menu doesn't take the keyboard: this replaces the selection
        m.run(vec![egui::Event::Text("X".into())]);
        assert_eq!(m.text, "abcX");
        assert!(m.item("Cut").unwrap().is_disabled());
        m.click("Paste");
        assert_eq!(m.selection(), Some(4..4));
    }

    #[test]
    fn a_password_cannot_be_cut_or_copied() {
        let mut m = Menu::new("hunter2", true);
        m.select(0, 7);
        m.right_click();
        assert!(m.item("Cut").is_none() && m.item("Copy").is_none());
        assert!(m.item("Paste").is_some() && m.item("Select All").is_some());
    }
}
