//! StatusNotifierItem (system tray) via `tray-icon` / `ksni`.
//! Closing the window hides to the tray; Quit on the menu exits the process.

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// What the tray menu asked the UI thread to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Show,
    /// Connect when idle, disconnect when a session is up.
    ToggleConnect,
    Quit,
}

/// Living tray icon; drop it to remove the item from the tray.
pub struct Handle {
    icon: TrayIcon,
    show: MenuItem,
    toggle: MenuItem,
    quit: MenuItem,
}

impl Handle {
    /// Register a StatusNotifierItem. Fails without a session bus (headless CI, SSH).
    pub fn try_new() -> Result<Self, String> {
        let menu = Menu::new();
        let show = MenuItem::new("Show Archway", true, None);
        let toggle = MenuItem::new("Connect", true, None);
        let quit = MenuItem::new("Quit", true, None);
        menu.append(&show).map_err(|e| e.to_string())?;
        menu.append(&PredefinedMenuItem::separator())
            .map_err(|e| e.to_string())?;
        menu.append(&toggle).map_err(|e| e.to_string())?;
        menu.append(&PredefinedMenuItem::separator())
            .map_err(|e| e.to_string())?;
        menu.append(&quit).map_err(|e| e.to_string())?;

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Archway — Disconnected")
            .with_icon(app_icon()?)
            .with_title("Archway")
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            icon,
            show,
            toggle,
            quit,
        })
    }

    /// Refresh the Connect/Disconnect label and the tooltip.
    pub fn set_status(&self, connected: bool, tooltip: &str) {
        self.toggle.set_text(if connected {
            "Disconnect"
        } else {
            "Connect"
        });
        let _ = self.icon.set_tooltip(Some(tooltip));
    }

    /// Menu and left-click actions waiting for this frame (non-blocking).
    pub fn poll(&self) -> Vec<Action> {
        let mut out = Vec::new();
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == self.show.id() {
                out.push(Action::Show);
            } else if ev.id == self.toggle.id() {
                out.push(Action::ToggleConnect);
            } else if ev.id == self.quit.id() {
                out.push(Action::Quit);
            }
        }
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            // Left click: bring the window back (GNOME often needs the menu for the rest).
            if matches!(
                ev,
                TrayIconEvent::Click {
                    button: tray_icon::MouseButton::Left,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                }
            ) {
                out.push(Action::Show);
            }
        }
        out
    }
}

fn app_icon() -> Result<Icon, String> {
    let data = eframe::icon_data::from_png_bytes(include_bytes!("../assets/archway-vpn-256.png"))
        .map_err(|e| e.to_string())?;
    Icon::from_rgba(data.rgba, data.width, data.height).map_err(|e| e.to_string())
}
