//! The look: colours for dark and light, fonts (IBM Plex, Lucide icons), sizes, and the widgets egui doesn't have
//! (cards, buttons that don't change size on hover, status pill, toggle, the logo).

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontFamily, FontId, Frame, Margin, RichText, Sense, Stroke,
    StrokeKind, TextStyle, Ui, Vec2, vec2,
};
use std::sync::LazyLock;

/// Lucide glyphs (assets/fonts/lucide.ttf, subset to these), by their Lucide names, except SHARE (`share-2`),
/// TERMINAL (`square-terminal`) and REFRESH (`refresh-cw`).
pub mod icon {
    macro_rules! icons {
        ($($name:ident = $code:literal),* $(,)?) => {
            $(pub const $name: &str = $code;)*
            #[cfg(test)]
            pub const ALL: &[(&str, &str)] = &[$((stringify!($name), $name)),*];
        };
    }
    icons! {
        PLUG = "\u{e37f}", PLUG_ZAP = "\u{e45c}", TRIANGLE_ALERT = "\u{e193}", COPY = "\u{e09e}", SHARE = "\u{e156}",
        TRASH = "\u{e18d}", PLUS = "\u{e13d}", CHECK = "\u{e06c}", X = "\u{e1b2}", SAVE = "\u{e14d}",
        TERMINAL = "\u{e20a}", SETTINGS = "\u{e154}", GLOBE = "\u{e0e8}", CHEVRON_RIGHT = "\u{e06f}",
        CHEVRON_DOWN = "\u{e06d}", ARROW_LEFT = "\u{e048}", EXTERNAL_LINK = "\u{e0b9}", REFRESH = "\u{e145}",
        CIRCLE_ALERT = "\u{e077}", HOURGLASS = "\u{e296}", LOG_IN = "\u{e10d}", LOCK = "\u{e10b}",
    }
}

/// Colours egui's `Visuals` has no slot for, plus the ones the widgets here use directly.
#[derive(Clone, Copy)]
pub struct Tokens {
    /// top bar, left pane, log drawer
    pub side: Color32,
    /// main area, cards, fields
    pub surface: Color32,
    /// the selected connection
    pub selected: Color32,
    pub hover: Color32,
    /// card borders and dividers
    pub border: Color32,
    /// fields and outlined buttons
    pub border_strong: Color32,
    pub text: Color32,
    /// field captions, banner bodies
    pub secondary: Color32,
    /// help and captions
    pub weak: Color32,
    pub disabled_bg: Color32,
    pub disabled_text: Color32,
    pub success: Color32,
    pub success_fill: Color32,
    /// in progress, and ⚠
    pub warning: Color32,
    pub busy_fill: Color32,
    pub danger: Color32,
    pub danger_line: Color32,
    pub danger_fill: Color32,
    /// the fill of a destructive confirm, under white text
    pub danger_button: Color32,
    pub info_fill: Color32,
    pub info_line: Color32,
    pub warn_fill: Color32,
    pub warn_line: Color32,
    /// keyboard focus, and the field a fix button points at
    pub focus: Color32,
}

const fn hex(s: u32) -> Color32 {
    Color32::from_rgb((s >> 16) as u8, (s >> 8) as u8, s as u8)
}

fn tint(c: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
}

const LIGHT: Tokens = Tokens {
    side: hex(0xf3f4f6),
    surface: hex(0xffffff),
    selected: hex(0xe6e8ec),
    hover: hex(0xe9eaee),
    border: hex(0xe2e4e9),
    border_strong: hex(0xd3d6dd),
    text: hex(0x15171c),
    secondary: hex(0x4b515c),
    weak: hex(0x5a606c),
    disabled_bg: hex(0xf3f4f6),
    disabled_text: hex(0x7d838d),
    success: hex(0x137140),
    success_fill: hex(0xe3f4ea),
    warning: hex(0x9a4800),
    busy_fill: hex(0xfdf1e3),
    danger: hex(0xa8202f),
    danger_line: hex(0xc62e40),
    danger_fill: hex(0xfdf0f1),
    danger_button: hex(0xa8202f),
    info_fill: hex(0xf4f8fe),
    info_line: hex(0xc9d8f0),
    warn_fill: hex(0xfdf4e8),
    warn_line: hex(0xf0d3ad),
    focus: hex(0x1f5fbf),
};

const DARK: Tokens = Tokens {
    side: hex(0x111317),
    surface: hex(0x181b20),
    selected: hex(0x262a31),
    hover: hex(0x22262d),
    border: hex(0x2a2e35),
    border_strong: hex(0x3a3f48),
    text: hex(0xeceef2),
    secondary: hex(0xc3c8d0),
    weak: hex(0x9aa1ad),
    disabled_bg: hex(0x1d2026),
    disabled_text: hex(0x6f7682),
    success: hex(0x5ad596),
    success_fill: hex(0x16301f),
    warning: hex(0xf0a65a),
    busy_fill: hex(0x33261a),
    danger: hex(0xff8a96),
    danger_line: hex(0xe5576a),
    danger_fill: hex(0x3a1c21),
    danger_button: hex(0xb3303f),
    info_fill: hex(0x172234),
    info_line: hex(0x2c4366),
    warn_fill: hex(0x30261a),
    warn_line: hex(0x5c4527),
    focus: hex(0x6ea0ff),
};

/// The colours for the theme `ui` is drawn in (follows the desktop's light/dark setting).
pub fn tokens(ui: &Ui) -> Tokens {
    if ui.visuals().dark_mode { DARK } else { LIGHT }
}

/// WCAG contrast ratio of two opaque colours, 1 to 21.
#[cfg(test)]
fn contrast(a: Color32, b: Color32) -> f32 {
    let lum = |c: Color32| {
        let ch = |v: u8| {
            let v = f32::from(v) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * ch(c.r()) + 0.7152 * ch(c.g()) + 0.0722 * ch(c.b())
    };
    let (x, y) = (lum(a), lum(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

// ---- sizes ----

/// Field captions and secondary lines.
pub const CAPTION: f32 = 13.0;
/// Help text and warnings under fields.
pub const SMALL: f32 = 12.5;
pub const CARD_RADIUS: u8 = 12;
const CARD_PADDING: i8 = 18;
/// The big button in the status card.
pub const ACTION_SIZE: Vec2 = vec2(150.0, 44.0);

// ---- fonts ----

static MEDIUM: LazyLock<FontFamily> = LazyLock::new(|| FontFamily::Name("medium".into()));
static STRONG: LazyLock<FontFamily> = LazyLock::new(|| FontFamily::Name("strong".into()));
static ICONS: LazyLock<FontFamily> = LazyLock::new(|| FontFamily::Name("icons".into()));

/// `family` once the fonts are loaded (they apply from the frame after `install`), else None.
fn loaded(ctx: &egui::Context, family: &FontFamily) -> Option<FontFamily> {
    ctx.fonts(|f| f.definitions().families.contains_key(family))
        .then(|| family.clone())
}

/// `family`, or the regular face until the fonts are loaded.
fn family(ctx: &egui::Context, family: &FontFamily) -> FontFamily {
    loaded(ctx, family).unwrap_or(FontFamily::Proportional)
}

/// Load the fonts, and from the next call on (fonts apply from the next frame on) the sizes and colours. Call it
/// every frame, and before the first one; it does nothing once both are done. It must not ask egui which fonts are
/// loaded: before the first frame that panics.
pub fn install(ctx: &egui::Context) {
    #[derive(Clone, Copy, Default, PartialEq)]
    enum Step {
        #[default]
        Fonts,
        Style,
        Done,
    }
    let id = egui::Id::unique("theme-install");
    let step = ctx.data(|d| d.get_temp::<Step>(id)).unwrap_or_default();
    match step {
        Step::Fonts => {
            ctx.set_fonts(fonts());
            ctx.data_mut(|d| d.insert_temp(id, Step::Style));
        }
        Step::Style => {
            for (theme, t) in [(egui::Theme::Dark, DARK), (egui::Theme::Light, LIGHT)] {
                ctx.style_mut_of(theme, |s| style(s, t, theme));
            }
            ctx.data_mut(|d| d.insert_temp(id, Step::Done));
        }
        Step::Done => {}
    }
    // without input nothing else repaints: the next step would wait for the first mouse move
    if step != Step::Done {
        ctx.request_repaint();
    }
}

fn fonts() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    let mut add = |name: &str, bytes: &'static [u8]| {
        fonts
            .font_data
            .insert(name.into(), egui::FontData::from_static(bytes).into());
    };
    add(
        "plex",
        include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf"),
    );
    add(
        "plex-medium",
        include_bytes!("../assets/fonts/IBMPlexSans-Medium.ttf"),
    );
    add(
        "plex-semibold",
        include_bytes!("../assets/fonts/IBMPlexSans-SemiBold.ttf"),
    );
    add(
        "plex-mono",
        include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf"),
    );
    add("lucide", include_bytes!("../assets/fonts/lucide.ttf"));
    add(
        "emoji",
        include_bytes!("../assets/fonts/NotoEmoji-Regular.ttf"),
    );
    // after each face: Lucide for ⚠ (assets/fonts/lucide.ttf maps it to its warning triangle), the only symbol in the
    // UI that Plex lacks, and Noto Emoji for emoji in connection names. egui's other fonts aren't bundled (eframe
    // without "default_fonts"), which saves 1 MB.
    let with_fallback =
        |first: &str| vec![first.to_string(), "lucide".to_string(), "emoji".to_string()];
    fonts
        .families
        .insert(FontFamily::Proportional, with_fallback("plex"));
    fonts
        .families
        .insert(FontFamily::Monospace, with_fallback("plex-mono"));
    fonts
        .families
        .insert(MEDIUM.clone(), with_fallback("plex-medium"));
    fonts
        .families
        .insert(STRONG.clone(), with_fallback("plex-semibold"));
    // a family of its own, so a private-use codepoint never falls through to another font; Plex after it only for
    // egui's replacement glyph (◻)
    fonts
        .families
        .insert(ICONS.clone(), vec!["lucide".into(), "plex".into()]);
    fonts
}

fn style(s: &mut egui::Style, t: Tokens, theme: egui::Theme) {
    s.text_styles
        .insert(TextStyle::Body, FontId::proportional(14.0));
    s.text_styles
        .insert(TextStyle::Button, FontId::proportional(14.0));
    s.text_styles
        .insert(TextStyle::Small, FontId::proportional(SMALL));
    s.text_styles
        .insert(TextStyle::Monospace, FontId::monospace(CAPTION));
    s.text_styles
        .insert(TextStyle::Heading, FontId::new(22.0, STRONG.clone()));
    s.spacing.interact_size.y = 36.0;
    s.spacing.button_padding = vec2(14.0, 8.0);
    s.spacing.item_spacing = vec2(10.0, 10.0);
    s.spacing.window_margin = Margin::same(20);
    s.spacing.menu_margin = Margin::same(6);
    s.spacing.icon_width = 18.0;
    s.spacing.icon_width_inner = 10.0;
    s.spacing.text_edit_width = 440.0;

    let v = &mut s.visuals;
    *v = theme.default_visuals();
    v.panel_fill = t.surface;
    v.window_fill = t.surface;
    v.extreme_bg_color = t.surface;
    v.faint_bg_color = t.side;
    v.hyperlink_color = t.focus;
    v.selection.bg_fill = tint(t.focus, 70);
    v.selection.stroke = Stroke::new(2.0, t.focus);
    v.warn_fg_color = t.warning;
    v.error_fg_color = t.danger;
    v.window_corner_radius = CornerRadius::same(CARD_RADIUS);
    v.menu_corner_radius = CornerRadius::same(10);
    v.window_stroke = Stroke::new(1.0, t.border);
    v.window_shadow = egui::Shadow {
        offset: [0, 16],
        blur: 40,
        spread: 0,
        color: Color32::from_black_alpha(64),
    };
    let r = CornerRadius::same(8);
    v.widgets.noninteractive.bg_fill = t.surface;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, t.border);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, t.text);
    v.widgets.noninteractive.corner_radius = r;
    for (w, fill, stroke) in [
        (&mut v.widgets.inactive, t.surface, t.border_strong),
        (&mut v.widgets.hovered, t.hover, t.border_strong),
        (&mut v.widgets.active, t.hover, t.text),
        (&mut v.widgets.open, t.hover, t.border_strong),
    ] {
        w.bg_fill = fill;
        w.weak_bg_fill = fill;
        w.bg_stroke = Stroke::new(1.0, stroke);
        w.fg_stroke = Stroke::new(1.5, t.text);
        w.corner_radius = r;
        w.expansion = 0.0;
    }
}

// ---- text ----

/// Semibold text (regular until the fonts are loaded).
pub fn strong(ui: &Ui, text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text.into())
        .family(family(ui.ctx(), &STRONG))
        .size(size)
}

/// The semibold font at `size` (regular until the fonts are loaded), for widgets that take a font, not text.
pub fn strong_font(ctx: &egui::Context, size: f32) -> FontId {
    FontId::new(size, family(ctx, &STRONG))
}

/// Medium-weight text (regular until the fonts are loaded): button labels, small emphasis.
pub fn medium(ui: &Ui, text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text.into())
        .family(family(ui.ctx(), &MEDIUM))
        .size(size)
}

/// Semibold text in the main text colour: titles and values.
pub fn title(ui: &Ui, text: impl Into<String>, size: f32) -> RichText {
    strong(ui, text, size).color(tokens(ui).text)
}

/// A field's caption, or a secondary line.
pub fn caption(ui: &Ui, text: impl Into<String>) -> RichText {
    RichText::new(text.into())
        .size(CAPTION)
        .color(tokens(ui).secondary)
}

/// Help text.
pub fn weak(ui: &Ui, text: impl Into<String>) -> RichText {
    RichText::new(text.into())
        .size(SMALL)
        .color(tokens(ui).weak)
}

/// Uppercase section caption ("Connections", "Advanced").
pub fn eyebrow(ui: &mut Ui, text: &str) {
    let t = tokens(ui);
    ui.label(
        strong(ui, text.to_uppercase(), 12.0)
            .extra_letter_spacing(0.72)
            .color(t.weak),
    );
}

/// `glyph` in the icon font (nothing until the fonts are loaded).
pub fn glyph(ui: &Ui, glyph: &str, size: f32, color: Color32) -> RichText {
    match loaded(ui.ctx(), &ICONS) {
        Some(f) => RichText::new(glyph).family(f).size(size).color(color),
        None => RichText::new(""),
    }
}

/// An icon (none if `glyph` is empty), then `text`. `color` PLACEHOLDER takes the widget's text colour.
pub fn with_icon(
    ui: &Ui,
    glyph: &str,
    text: &str,
    size: f32,
    color: Color32,
    bold: bool,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let format = |font_id| egui::TextFormat {
        font_id,
        color,
        valign: Align::Center,
        ..Default::default()
    };
    if !glyph.is_empty()
        && let Some(icons) = loaded(ui.ctx(), &ICONS)
    {
        job.append(glyph, 0.0, format(FontId::new(size * 1.1, icons)));
        job.append(" ", 0.0, format(FontId::proportional(size)));
    }
    let family = if bold {
        family(ui.ctx(), &MEDIUM)
    } else {
        FontFamily::Proportional
    };
    job.append(text, 0.0, format(FontId::new(size, family)));
    job
}

/// Screen readers get `label`: the visible text starts with an icon from the private use area, or the widget's
/// caption is a separate label.
pub fn labelled(r: egui::Response, label: &str) -> egui::Response {
    r.ctx.accesskit_node_builder(r.id, |n| n.set_label(label));
    r
}

/// Medium text that counts up (a duration, bytes) in a box as wide as `template`, so it doesn't jiggle when the
/// digits change.
pub fn ticking(ui: &mut Ui, value: &str, template: &str, size: f32) -> egui::Response {
    let font = FontId::new(size, family(ui.ctx(), &MEDIUM));
    let width = ui
        .painter()
        .layout_no_wrap(template.into(), font, Color32::WHITE)
        .size()
        .x;
    let text = medium(ui, value, size).color(tokens(ui).text);
    ui.add_sized(
        vec2(width, size * 1.5),
        egui::Label::new(text).wrap_mode(egui::TextWrapMode::Extend),
    )
}

// ---- buttons ----

/// What a button is for.
#[derive(Clone, Copy, PartialEq)]
pub enum Tone {
    /// the main action: filled in the text colour
    Primary,
    /// stopping or removing something: outline, red text
    Danger,
    /// a dialog's destructive confirm: red fill
    DangerFill,
    /// anything else: outline
    Plain,
}

/// The big button in the status card (Connect, Disconnect, Cancel).
pub fn action(ui: &mut Ui, enabled: bool, tone: Tone, text: &str) -> egui::Response {
    let job = with_icon(ui, "", text, 15.0, Color32::PLACEHOLDER, true);
    framed(ui, enabled, tone, job.into(), ACTION_SIZE, 10, text)
}

/// A button with an optional icon (`""` for none) in `tone`, at the normal height.
pub fn solid(ui: &mut Ui, enabled: bool, tone: Tone, icon: &str, text: &str) -> egui::Response {
    let job = with_icon(ui, icon, text, 14.0, Color32::PLACEHOLDER, true);
    framed(ui, enabled, tone, job.into(), vec2(0.0, 36.0), 8, text)
}

/// A plain outlined button with an optional icon.
pub fn button(ui: &mut Ui, enabled: bool, icon: &str, text: &str) -> egui::Response {
    solid(ui, enabled, Tone::Plain, icon, text)
}

/// Text, fill and border of a button in `tone`, for its state.
fn button_look(
    t: Tokens,
    tone: Tone,
    enabled: bool,
    hovered: bool,
    pressed: bool,
) -> (Color32, Color32, Color32) {
    if !enabled {
        return (t.disabled_text, t.disabled_bg, t.border);
    }
    // how far the fill moves on hover and press: towards the surface for dark fills, deeper for light ones
    let k = if pressed {
        0.24
    } else if hovered {
        0.12
    } else {
        0.0
    };
    match tone {
        Tone::Primary => (t.surface, t.text.lerp_to_gamma(t.surface, k), t.text),
        Tone::DangerFill => (
            Color32::WHITE,
            t.danger_button.lerp_to_gamma(Color32::BLACK, k),
            t.danger_button,
        ),
        Tone::Danger => (
            t.danger,
            t.surface.lerp_to_gamma(t.danger_line, k * 0.6),
            t.danger_line,
        ),
        Tone::Plain => (
            t.text,
            t.surface.lerp_to_gamma(t.text, k * 0.6),
            t.border_strong,
        ),
    }
}

/// An outlined or filled button in `tone`.
fn framed(
    ui: &mut Ui,
    enabled: bool,
    tone: Tone,
    text: egui::WidgetText,
    min: Vec2,
    radius: u8,
    label: &str,
) -> egui::Response {
    let t = tokens(ui);
    painted(
        ui,
        enabled,
        text,
        min,
        vec2(14.0, 0.0),
        radius,
        label,
        |hovered, pressed| button_look(t, tone, enabled, hovered, pressed),
    )
}

/// A button without a frame until it's hovered; `on` keeps it pressed (a toggle that's on).
#[allow(clippy::too_many_arguments)]
fn ghost(
    ui: &mut Ui,
    enabled: bool,
    text: egui::WidgetText,
    min: Vec2,
    padding: Vec2,
    radius: u8,
    on: bool,
    label: &str,
) -> egui::Response {
    let t = tokens(ui);
    painted(
        ui,
        enabled,
        text,
        min,
        padding,
        radius,
        label,
        |hovered, _| {
            let fill = if on {
                t.border
            } else if enabled && hovered {
                t.hover
            } else {
                Color32::TRANSPARENT
            };
            (
                if enabled { t.text } else { t.disabled_text },
                fill,
                Color32::TRANSPARENT,
            )
        },
    )
}

/// A button painted here, as egui's change size when their frame appears on hover, which moves what's next to
/// them. `look` gives text, fill and border colours for (hovered, pressed).
#[allow(clippy::too_many_arguments)]
fn painted(
    ui: &mut Ui,
    enabled: bool,
    text: egui::WidgetText,
    min: Vec2,
    padding: Vec2,
    radius: u8,
    label: &str,
    look: impl FnOnce(bool, bool) -> (Color32, Color32, Color32),
) -> egui::Response {
    let focus = tokens(ui).focus;
    let r = ui
        .add_enabled_ui(enabled, |ui| {
            let galley = text.into_galley(
                ui,
                Some(egui::TextWrapMode::Extend),
                f32::INFINITY,
                TextStyle::Button,
            );
            let (rect, r) =
                ui.allocate_exact_size((galley.size() + 2.0 * padding).max(min), Sense::click());
            r.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, label));
            let (ink, fill, stroke) = look(r.hovered(), r.is_pointer_button_down_on());
            let p = ui.painter();
            let radius = CornerRadius::same(radius);
            p.rect_filled(rect, radius, fill);
            p.rect_stroke(rect, radius, Stroke::new(1.0, stroke), StrokeKind::Inside);
            if r.has_focus() {
                p.rect_stroke(rect, radius, Stroke::new(2.0, focus), StrokeKind::Inside);
            }
            p.galley(rect.center() - galley.size() / 2.0, galley, ink);
            r
        })
        .inner;
    labelled(r, label)
}

/// A frameless button with an icon, for secondary actions.
pub fn quiet(ui: &mut Ui, icon: &str, text: &str) -> egui::Response {
    let job = with_icon(ui, icon, text, 14.0, Color32::PLACEHOLDER, false);
    ghost(
        ui,
        true,
        job.into(),
        vec2(0.0, 32.0),
        vec2(10.0, 6.0),
        6,
        false,
        text,
    )
}

/// A square icon-only button; `on` draws it pressed (a toggle that's on).
pub fn icon_button(ui: &mut Ui, icon: &str, label: &str, on: bool) -> egui::Response {
    let text = glyph(ui, icon, 18.0, Color32::PLACEHOLDER).into();
    ghost(ui, true, text, vec2(36.0, 36.0), Vec2::ZERO, 8, on, label).on_hover_text(label)
}

/// egui's spinner, but repainting at 20 fps instead of every frame: a full window repaint at the display's refresh
/// rate costs ~10% of a core for nothing.
pub fn spinner(ui: &mut Ui, size: f32, color: Color32) -> egui::Response {
    let (rect, r) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    r.widget_info(|| egui::WidgetInfo::new(egui::Role::ProgressIndicator));
    if ui.is_rect_visible(rect) {
        ui.request_repaint_after(std::time::Duration::from_millis(50));
        // the same arc as egui::Spinner
        let radius = size / 2.0 - 2.0;
        let n = (radius.round() as u32).clamp(8, 128);
        let time = ui.input(|i| i.time);
        let start = time * std::f64::consts::TAU;
        let end = start + 240f64.to_radians() * time.sin();
        let points = (0..n)
            .map(|i| {
                let (sin, cos) = egui::lerp(start..=end, f64::from(i) / f64::from(n)).sin_cos();
                rect.center() + radius * vec2(cos as f32, sin as f32)
            })
            .collect();
        ui.painter()
            .add(egui::Shape::line(points, Stroke::new(2.4, color)));
    }
    r
}

/// Side of `small_icon_button`.
pub const SMALL_BUTTON: f32 = 30.0;

/// A small square icon-only button, for actions inside a list row; `color` PLACEHOLDER is the text colour.
pub fn small_icon_button(
    ui: &mut Ui,
    enabled: bool,
    icon: &str,
    label: &str,
    color: Color32,
) -> egui::Response {
    let text = glyph(
        ui,
        icon,
        16.0,
        if enabled { color } else { Color32::PLACEHOLDER },
    )
    .into();
    ghost(
        ui,
        enabled,
        text,
        Vec2::splat(SMALL_BUTTON),
        Vec2::ZERO,
        6,
        false,
        label,
    )
    .on_hover_text(label)
}

/// How long a copy button says "Copied".
const COPIED_FOR: f64 = 2.0;

/// Copies `text()` (only called on a click: it may be the whole log) and shows a check and "Copied" for two seconds,
/// at the same size: outlined at `width`, or icon-only for None. `id` keeps the state, so it's unique per button.
pub fn copy_button(
    ui: &mut Ui,
    id: egui::Id,
    text: impl FnOnce() -> String,
    label: &str,
    width: Option<f32>,
) -> egui::Response {
    let t = tokens(ui);
    let now = ui.input(|i| i.time);
    let at = ui
        .data(|d| d.get_temp::<f64>(id))
        .filter(|at| now - at < COPIED_FOR);
    let (glyph_s, shown, color) = if at.is_some() {
        (icon::CHECK, "Copied", t.success)
    } else {
        (icon::COPY, label, Color32::PLACEHOLDER)
    };
    let r = match width {
        None => small_icon_button(ui, true, glyph_s, shown, color),
        Some(w) => framed(
            ui,
            true,
            Tone::Plain,
            with_icon(ui, glyph_s, shown, 14.0, color, true).into(),
            vec2(w, 36.0),
            8,
            shown,
        ),
    };
    if r.clicked() {
        ui.ctx().copy_text(text());
        ui.data_mut(|d| d.insert_temp(id, now));
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_secs_f64(COPIED_FOR));
    } else if let Some(at) = at {
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_secs_f64(
                at + COPIED_FOR - now + 0.01,
            ));
    }
    r
}

/// A full-width dashed button at the end of a list ("New Connection").
pub fn list_button(ui: &mut Ui, enabled: bool, icon: &str, text: &str) -> egui::Response {
    let t = tokens(ui);
    let (rect, r) = ui.allocate_exact_size(
        vec2(ui.available_width(), 40.0),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    r.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, text));
    let p = ui.painter();
    if enabled && r.hovered() {
        p.rect_filled(rect, CornerRadius::same(8), t.hover);
    }
    let rr = rect.shrink(0.5);
    let corners = [
        rr.left_top(),
        rr.right_top(),
        rr.right_bottom(),
        rr.left_bottom(),
        rr.left_top(),
    ];
    p.extend(egui::Shape::dashed_line(
        &corners,
        Stroke::new(1.0, t.border_strong),
        4.0,
        3.0,
    ));
    if r.has_focus() {
        p.rect_stroke(
            rect,
            CornerRadius::same(8),
            Stroke::new(2.0, t.focus),
            StrokeKind::Inside,
        );
    }
    let color = if enabled {
        t.secondary
    } else {
        t.disabled_text
    };
    let galley = egui::WidgetText::from(with_icon(ui, icon, text, 14.0, color, false)).into_galley(
        ui,
        Some(egui::TextWrapMode::Extend),
        f32::INFINITY,
        TextStyle::Button,
    );
    ui.painter().galley(
        egui::pos2(rect.left() + 12.0, rect.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    r
}

// ---- containers ----

/// The box behind a card, without its margin.
fn card_frame(t: Tokens) -> Frame {
    Frame::new()
        .fill(t.surface)
        .stroke(Stroke::new(1.0, t.border))
        .corner_radius(CARD_RADIUS)
}

/// A rounded, bordered box for one group of things.
pub fn card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    card_frame(tokens(ui))
        .inner_margin(Margin::symmetric(CARD_PADDING, 16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

/// Title and an optional one-line explanation at the top of a card.
pub fn card_title(ui: &mut Ui, title_text: &str, sub: Option<&str>) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.label(title(ui, title_text, 15.0));
        if let Some(sub) = sub {
            ui.label(weak(ui, sub));
        }
    });
    ui.add_space(4.0);
}

/// What a banner is about.
#[derive(Clone, Copy)]
pub enum BannerKind {
    /// something to do: sign in, enter a password
    Info,
    /// it's taking long
    Warning,
    /// it failed
    Danger,
}

/// A tinted, full-width box with an icon: messages that need attention.
pub fn banner(ui: &mut Ui, kind: BannerKind, icon: &str, add: impl FnOnce(&mut Ui)) {
    let t = tokens(ui);
    let (fill, line, ink) = match kind {
        BannerKind::Info => (t.info_fill, t.info_line, t.focus),
        BannerKind::Warning => (t.warn_fill, t.warn_line, t.warning),
        BannerKind::Danger => (t.danger_fill, tint(t.danger_line, 110), t.danger),
    };
    Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, line))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(16, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.label(glyph(ui, icon, 20.0, ink));
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    add(ui);
                });
            });
        });
}

/// What the user did with an error banner.
#[derive(Default, PartialEq, Debug)]
pub struct BannerAction {
    pub fix: bool,
    pub dismiss: bool,
}

/// A red banner for an error. A single `diag` reads as a title, the reason, and the advice or (`fix`) a button that
/// goes to the field; anything else (several errors) stays the monospace text. `dismiss` adds a close button.
pub fn error_banner(ui: &mut Ui, text: &str, fix: Option<&str>, dismiss: bool) -> BannerAction {
    let t = tokens(ui);
    let mut act = BannerAction::default();
    let parsed = crate::diag::Diag::parse(text);
    banner(ui, BannerKind::Danger, icon::CIRCLE_ALERT, |ui| {
        ui.horizontal_top(|ui| {
            let right = if dismiss { 34.0 } else { 0.0 } + fix.map_or(0.0, |_| 230.0);
            ui.vertical(|ui| {
                ui.set_width((ui.available_width() - right).max(160.0));
                ui.spacing_mut().item_spacing.y = 4.0;
                match &parsed {
                    Some(d) => {
                        ui.add(
                            egui::Label::new(title(
                                ui,
                                crate::diag::capitalised(&d.headline),
                                14.0,
                            ))
                            .wrap(),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(crate::diag::sentence(&d.note)).color(t.secondary),
                            )
                            .wrap(),
                        );
                        if fix.is_none() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(crate::diag::sentence(&d.help))
                                        .color(t.secondary),
                                )
                                .wrap(),
                            );
                        }
                    }
                    None => {
                        ui.add(
                            egui::Label::new(RichText::new(text).monospace().color(t.text)).wrap(),
                        );
                    }
                }
            });
            ui.with_layout(egui::Layout::right_to_left(Align::Min), |ui| {
                if dismiss
                    && small_icon_button(ui, true, icon::X, "Dismiss", Color32::PLACEHOLDER)
                        .clicked()
                {
                    act.dismiss = true;
                }
                if let Some(label) = fix
                    && button(ui, true, "", label).clicked()
                {
                    act.fix = true;
                }
            });
        });
    });
    act
}

/// A card that folds open: chevron, title, a one-line summary of what's inside, ⚠ when `marked`. Starts closed.
/// Whether it's open is kept per title, so it stays open when another connection is selected.
pub fn fold_card(
    ui: &mut Ui,
    title_text: &str,
    summary: &str,
    marked: bool,
    body: impl FnOnce(&mut Ui),
) {
    let t = tokens(ui);
    let id = ui.make_persistent_id(("fold", title_text));
    let mut open = ui
        .data_mut(|d| d.get_persisted::<bool>(id))
        .unwrap_or(false);
    card_frame(t)
        .inner_margin(Margin::symmetric(CARD_PADDING, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let (rect, r) =
                ui.allocate_exact_size(vec2(ui.available_width(), 24.0), Sense::click());
            if r.clicked() {
                open = !open;
                ui.data_mut(|d| d.insert_persisted(id, open));
            }
            r.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, title_text));
            ui.ctx()
                .accesskit_node_builder(r.id, |n| n.set_expanded(open));
            let p = ui.painter();
            if r.has_focus() {
                p.rect_stroke(
                    rect.expand(4.0),
                    CornerRadius::same(8),
                    Stroke::new(2.0, t.focus),
                    StrokeKind::Outside,
                );
            }
            let mut x = rect.left();
            let mut right = rect.right();
            if let Some(icons) = loaded(ui.ctx(), &ICONS) {
                let chevron = if open {
                    icon::CHEVRON_DOWN
                } else {
                    icon::CHEVRON_RIGHT
                };
                p.text(
                    egui::pos2(x, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    chevron,
                    FontId::new(16.0, icons.clone()),
                    t.secondary,
                );
                x += 28.0;
                if marked {
                    p.text(
                        rect.right_center(),
                        egui::Align2::RIGHT_CENTER,
                        icon::TRIANGLE_ALERT,
                        FontId::new(16.0, icons),
                        t.warning,
                    );
                    right -= 26.0;
                }
            }
            let tr = p.text(
                egui::pos2(x, rect.center().y),
                egui::Align2::LEFT_CENTER,
                title_text,
                FontId::new(14.5, family(ui.ctx(), &STRONG)),
                t.text,
            );
            // the summary sits at the right, and gets what's left after the title
            let room = right - tr.right() - 16.0;
            let summary =
                egui::WidgetText::from(RichText::new(summary).size(CAPTION).color(t.weak))
                    .into_galley(
                        ui,
                        Some(egui::TextWrapMode::Truncate),
                        room.max(0.0),
                        TextStyle::Body,
                    );
            ui.painter().galley(
                egui::pos2(
                    right - summary.size().x,
                    rect.center().y - summary.size().y / 2.0,
                ),
                summary,
                t.weak,
            );
            if open {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.add_space(28.0);
                    ui.vertical(|ui| body(ui));
                });
            }
        });
}

/// A small card with a caption over one value (drawn by `value`, which may add a copy button), for the connected view.
pub fn stat(ui: &mut Ui, label: &str, width: f32, value: impl FnOnce(&mut Ui)) {
    let t = tokens(ui);
    card_frame(t)
        .corner_radius(10)
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(width);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                ui.label(RichText::new(label).size(SMALL).color(t.weak));
                ui.horizontal(|ui| {
                    ui.set_min_height(28.0);
                    value(ui);
                });
            });
        });
}

// ---- small widgets ----

/// What state a pill shows.
#[derive(Clone, Copy, PartialEq)]
pub enum PillKind {
    Idle,
    Busy,
    Connected,
}

/// The connection state, in a rounded tag.
pub fn pill(ui: &mut Ui, kind: PillKind, text: &str) -> egui::Response {
    let t = tokens(ui);
    let (fill, ink) = match kind {
        PillKind::Idle => (t.side, t.secondary),
        PillKind::Busy => (t.busy_fill, t.warning),
        PillKind::Connected => (t.success_fill, t.success),
    };
    let galley = ui.painter().layout_no_wrap(
        text.to_string(),
        FontId::new(12.5, family(ui.ctx(), &STRONG)),
        ink,
    );
    let (rect, r) = ui.allocate_exact_size(vec2(galley.size().x + 20.0, 24.0), Sense::hover());
    r.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, text));
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(12), fill);
    p.galley(
        rect.left_center() + vec2(10.0, -galley.size().y / 2.0),
        galley,
        ink,
    );
    r
}

/// An on/off switch with its label (one widget: both toggle it) and an optional explanation under it.
pub fn toggle(ui: &mut Ui, on: &mut bool, label: &str, help: Option<&str>) -> egui::Response {
    const SWITCH: Vec2 = vec2(40.0, 22.0);
    const GAP: f32 = 12.0;
    let t = tokens(ui);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        let text = egui::WidgetText::from(RichText::new(label).color(t.text)).into_galley(
            ui,
            Some(egui::TextWrapMode::Extend),
            f32::INFINITY,
            TextStyle::Body,
        );
        let (rect, mut r) = ui.allocate_exact_size(
            vec2(SWITCH.x + GAP + text.size().x, SWITCH.y.max(text.size().y)),
            Sense::click(),
        );
        if r.clicked() {
            *on = !*on;
            r.mark_changed();
        }
        r.widget_info(|| egui::WidgetInfo::selected(egui::Role::CheckBox, true, *on, label));
        let switch = egui::Rect::from_min_size(
            egui::pos2(rect.left(), rect.center().y - SWITCH.y / 2.0),
            SWITCH,
        );
        let k = ui.ctx().animate_bool_responsive(r.id, *on);
        let off = if r.hovered() { t.weak } else { t.border_strong };
        let p = ui.painter();
        p.rect_filled(switch, CornerRadius::same(11), off.lerp_to_gamma(t.text, k));
        if r.has_focus() {
            p.rect_stroke(
                switch.expand(2.0),
                CornerRadius::same(13),
                Stroke::new(2.0, t.focus),
                StrokeKind::Outside,
            );
        }
        let knob = if ui.visuals().dark_mode {
            t.side.lerp_to_gamma(Color32::WHITE, 1.0 - k)
        } else {
            Color32::WHITE
        };
        p.circle_filled(
            egui::pos2(
                egui::lerp((switch.left() + 11.0)..=(switch.right() - 11.0), k),
                switch.center().y,
            ),
            8.0,
            knob,
        );
        p.galley(
            egui::pos2(switch.right() + GAP, rect.center().y - text.size().y / 2.0),
            text,
            t.text,
        );
        if let Some(help) = help {
            ui.horizontal(|ui| {
                ui.add_space(SWITCH.x + GAP - ui.spacing().item_spacing.x);
                ui.label(weak(ui, help));
            });
        }
        r
    })
    .inner
}

/// The app icon: two arches on a blue square, as assets/archway-vpn.svg.
pub fn logo(ui: &mut Ui, size: f32) -> egui::Response {
    // assets/archway-vpn.svg: a 512 box with the square at 32..480
    const SQUARE_AT: f32 = 32.0;
    const SQUARE: f32 = 448.0;
    const BLUE: Color32 = hex(0x1c71d8);
    let (rect, response) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    let p = ui.painter();
    let s = size / SQUARE;
    let at = |x: f32, y: f32| rect.min + vec2((x - SQUARE_AT) * s, (y - SQUARE_AT) * s);
    p.rect_filled(rect, CornerRadius::same((104.0 * s) as u8), BLUE);
    // `white` is how much white is mixed into the blue: opaque, so the caps don't blend twice with the line
    let arch = |left: f32, right: f32, top: f32, white: f32, width: f32| {
        let (cx, radius) = ((left + right) / 2.0, (right - left) / 2.0);
        let color = BLUE.lerp_to_gamma(Color32::WHITE, white);
        let mut pts = vec![at(left, 404.0)];
        for i in 0..=24 {
            let a = std::f32::consts::PI * (1.0 + i as f32 / 24.0);
            pts.push(at(cx + radius * a.cos(), top + radius * a.sin()));
        }
        pts.push(at(right, 404.0));
        // round caps, as in the svg
        for end in [pts[0], pts[pts.len() - 1]] {
            p.circle_filled(end, width * s / 2.0, color);
        }
        p.add(egui::Shape::line(pts, Stroke::new(width * s, color)));
    };
    arch(132.0, 380.0, 268.0, 1.0, 38.0);
    arch(204.0, 308.0, 276.0, 0.6, 28.0);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::accesskit::{Action, ActionRequest, Role};

    #[test]
    fn tokens_have_readable_contrast() {
        for (name, t) in [("light", LIGHT), ("dark", DARK)] {
            for (what, fg, bg, min) in [
                ("text", t.text, t.surface, 4.5),
                ("text on ground", t.text, t.side, 4.5),
                ("secondary", t.secondary, t.surface, 4.5),
                ("weak", t.weak, t.surface, 4.5),
                ("weak on ground", t.weak, t.side, 4.5),
                ("primary button", t.surface, t.text, 4.5),
                ("success", t.success, t.surface, 4.5),
                ("success on its fill", t.success, t.success_fill, 4.5),
                ("busy", t.warning, t.busy_fill, 4.5),
                ("danger", t.danger, t.surface, 4.5),
                ("danger on its fill", t.danger, t.danger_fill, 4.5),
                ("disabled", t.disabled_text, t.disabled_bg, 3.0),
                ("danger line", t.danger_line, t.surface, 3.0),
                ("destructive button", Color32::WHITE, t.danger_button, 4.5),
                ("focus", t.focus, t.surface, 3.0),
            ] {
                let c = contrast(fg, bg);
                assert!(c >= min, "{name}: {what} has contrast {c:.2}, needs {min}");
            }
        }
    }

    fn frame(
        ctx: &egui::Context,
        time: f64,
        events: Vec<egui::Event>,
        add: impl FnMut(&mut Ui),
    ) -> Vec<(egui::accesskit::NodeId, egui::accesskit::Node)> {
        let mut add = add;
        let mut out = ctx.run_ui(
            egui::RawInput {
                time: Some(time),
                events,
                ..Default::default()
            },
            |ui| add(ui),
        );
        let nodes = out
            .platform_output
            .accesskit_update
            .take()
            .map(|u| u.nodes)
            .unwrap_or_default();
        out.drop_without_applying_deltas();
        nodes
    }

    #[test]
    fn copy_button_shows_copied_at_the_same_size() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut rects = vec![];
        let mut draw = |ui: &mut Ui| {
            rects.push(
                copy_button(
                    ui,
                    egui::Id::unique("c"),
                    || "10.0.0.1".into(),
                    "Copy",
                    Some(96.0),
                )
                .rect,
            )
        };
        for t in [0.0, 0.1, 0.2] {
            frame(&ctx, t, vec![], &mut draw);
        }
        let nodes = frame(&ctx, 0.3, vec![], &mut draw);
        let (id, _) = nodes
            .iter()
            .find(|(_, n)| n.role() == Role::Button && n.label() == Some("Copy"))
            .expect("Copy button");
        let click = egui::Event::AccessKitActionRequest(ActionRequest {
            action: Action::Click,
            target_tree: egui::accesskit::TreeId::ROOT,
            target_node: *id,
            data: None,
        });
        frame(&ctx, 0.4, vec![click], &mut draw);
        let nodes = frame(&ctx, 0.5, vec![], &mut draw);
        assert!(
            nodes
                .iter()
                .any(|(_, n)| n.role() == Role::Button && n.label() == Some("Copied")),
            "Copied after the click"
        );
        let nodes = frame(&ctx, 2.6, vec![], &mut draw);
        assert!(
            nodes
                .iter()
                .any(|(_, n)| n.role() == Role::Button && n.label() == Some("Copy")),
            "back to Copy after 2 s"
        );
        assert!(
            rects.windows(2).all(|w| w[0] == w[1]),
            "the button kept its size: {rects:?}"
        );
    }
}
