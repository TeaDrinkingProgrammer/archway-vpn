//! OpenVPN 3 Linux over D-Bus, as the user. Its D-Bus-activated services do the privileged work (tun device, routes,
//! DNS) under their own policy, so Archway needs no root for it. The config is imported single-use and not
//! persistent, so the tls-auth key in it never reaches the disk; the username and token are handed over through the
//! session's user-input queue, never in a file or on a command line.

use crate::net::{IfName, Secret};
use serde::de::DeserializeOwned;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zbus::blocking::Connection;
use zbus::zvariant::{DynamicType, OwnedObjectPath};

const CONFIG: &str = "net.openvpn.v3.configuration";
const SESSIONS: &str = "net.openvpn.v3.sessions";

/// `StatusMajor::CONNECTION` and the minors that matter (openvpn3-linux `src/dbus/constants.hpp`).
const CONNECTION: u32 = 2;
const CONNECTED: u32 = 7;
const DISCONNECTED: u32 = 9;
const FAILED: u32 = 10;
const AUTH_FAILED: u32 = 11;
const RECONNECTING: u32 = 12;
const DONE: u32 = 16;
/// `CFG_REQUIRE_USER`: the session asks for the username and password again
const REQUIRE_USER: u32 = 4;

/// The user-input queue's type and group for a username and password.
const CREDENTIALS: (u32, u32) = (1, 1);

pub fn install_hint() -> String {
    crate::diag(
        "error",
        "OpenVPN 3 Linux isn't installed",
        "Azure VPN connections run on it",
        "install the archway-vpn-openvpn package, or openvpn3-client. Debian 13 and Ubuntu 26.04 and newer ship it; on \
         Fedora add the dsommers/openvpn3 Copr (https://copr.fedorainfracloud.org/coprs/dsommers/openvpn3/), on Ubuntu 24.04 and Debian 12 \
         OpenVPN's repository (https://community.openvpn.net/openvpn/wiki/OpenVPN3Linux), on Arch the AUR package openvpn3",
    )
}

fn connect_error(note: &str) -> String {
    crate::diag(
        "error",
        "the Azure VPN gateway refused the connection",
        note,
        "the log has the details",
    )
}

pub struct OpenVpn3 {
    bus: Connection,
}

pub struct Session<'a> {
    bus: &'a Connection,
    path: OwnedObjectPath,
    /// while connecting: the session object may not be exported yet, so "does not exist" is retried until this is set
    retry: Cell<Option<&'a AtomicBool>>,
}

impl OpenVpn3 {
    /// The system bus, if OpenVPN 3 Linux is installed (its services can be started on it).
    pub fn connect() -> Result<Self, String> {
        let bus = Connection::system().map_err(|e| {
            crate::diag(
                "error",
                "the system D-Bus can't be reached",
                &e.to_string(),
                "Azure VPN connections need it to talk to OpenVPN 3 Linux; restart your session and try again",
            )
        })?;
        let names: Vec<String> = call(
            &bus,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "ListActivatableNames",
            &(),
            None,
        )?;
        if !names.iter().any(|n| n == CONFIG) || !names.iter().any(|n| n == SESSIONS) {
            return Err(install_hint());
        }
        Ok(Self { bus })
    }

    /// Import `config` under `name`, start a session, hand over the credentials and connect. Returns once connected;
    /// Err when the gateway refuses or `cancel` is set while connecting (the session is gone then).
    pub fn start<'a>(
        &'a self,
        name: &str,
        config: &Secret,
        username: &str,
        token: &Secret,
        cancel: &'a AtomicBool,
        log: &dyn Fn(String),
    ) -> Result<Session<'a>, String> {
        let cfg: OwnedObjectPath = call(
            &self.bus,
            CONFIG,
            "/net/openvpn/v3/configuration",
            CONFIG,
            "Import",
            &(name, config.expose(), true, false),
            Some(cancel),
        )?;
        let path = call::<OwnedObjectPath>(
            &self.bus,
            SESSIONS,
            "/net/openvpn/v3/sessions",
            SESSIONS,
            "NewTunnel",
            &(&cfg,),
            Some(cancel),
        )
        .inspect_err(|_| {
            // single-use configs go with their session; without one, remove it here (it holds the tls-auth key)
            let _ = call::<()>(&self.bus, CONFIG, cfg.as_str(), CONFIG, "Remove", &(), None);
        })?;
        log(format!("OpenVPN 3: session {}", path.as_str()));
        let s = Session {
            bus: &self.bus,
            path,
            retry: Cell::new(Some(cancel)),
        };
        s.credentials(username, token, cancel, log)?;
        if cancel.load(Ordering::SeqCst) {
            return Ok(s);
        }
        s.method::<()>("Connect", &())?;
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut last = String::new();
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Ok(s);
            }
            let (major, minor, msg) = s.status()?;
            if msg != last {
                log(format!("OpenVPN 3: {msg}"));
                last = msg.clone();
            }
            match (major, minor) {
                (CONNECTION, CONNECTED) => {
                    s.retry.set(None);
                    return Ok(s);
                }
                (CONNECTION, AUTH_FAILED) => {
                    return Err(connect_error(
                        "It didn't accept the sign-in. Your account may not be allowed on this VPN.",
                    ));
                }
                (CONNECTION, FAILED | DISCONNECTED | DONE) => {
                    return Err(connect_error(&format!("OpenVPN 3 reported: {msg}")));
                }
                _ if Instant::now() > deadline => {
                    return Err(connect_error("No connection after 90 seconds."));
                }
                _ => std::thread::sleep(Duration::from_millis(500)),
            }
        }
    }
}

impl Session<'_> {
    fn method<R: DeserializeOwned + zbus::zvariant::Type>(
        &self,
        method: &str,
        body: &(impl serde::Serialize + DynamicType),
    ) -> Result<R, String> {
        call(
            self.bus,
            SESSIONS,
            self.path.as_str(),
            SESSIONS,
            method,
            body,
            self.retry.get(),
        )
    }

    fn property<R: TryFrom<zbus::zvariant::OwnedValue>>(&self, name: &str) -> Result<R, String> {
        let v: zbus::zvariant::OwnedValue = call(
            self.bus,
            SESSIONS,
            self.path.as_str(),
            "org.freedesktop.DBus.Properties",
            "Get",
            &(SESSIONS, name),
            self.retry.get(),
        )?;
        R::try_from(v).map_err(|_| format!("OpenVPN 3: unexpected type of {name}"))
    }

    /// Answer the session's username and password requests until it's ready to connect.
    fn credentials(
        &self,
        username: &str,
        token: &Secret,
        cancel: &AtomicBool,
        log: &dyn Fn(String),
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !cancel.load(Ordering::SeqCst) {
            let Err(not_ready) = self.method::<()>("Ready", &()) else {
                return Ok(());
            };
            let ids: Vec<u32> = self.method("UserInputQueueCheck", &CREDENTIALS)?;
            for id in &ids {
                let (_, _, _, name, _, hidden): (u32, u32, u32, String, String, bool) =
                    self.method("UserInputQueueFetch", &(CREDENTIALS.0, CREDENTIALS.1, *id))?;
                let value = if hidden || name.contains("pass") {
                    token.expose()
                } else {
                    username
                };
                self.method::<()>(
                    "UserInputProvide",
                    &(CREDENTIALS.0, CREDENTIALS.1, *id, value),
                )?;
                log(format!(
                    "OpenVPN 3: provided {name} ({} characters)",
                    value.len()
                ));
            }
            if ids.is_empty() {
                if Instant::now() > deadline {
                    return Err(not_ready);
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        }
        Ok(())
    }

    /// (major, minor, message)
    fn status(&self) -> Result<(u32, u32, String), String> {
        let v: zbus::zvariant::Structure = self.property("status")?;
        v.try_into()
            .map_err(|_| "OpenVPN 3: unexpected type of status".to_string())
    }

    /// The tun interface openvpn3 created; it can lag the connected status by a moment.
    pub fn device(&self) -> Result<IfName, String> {
        let mut last = String::new();
        for _ in 0..10 {
            let name: String = self.property("device_name")?;
            match name.parse() {
                Ok(n) => return Ok(n),
                Err(e) => last = format!("OpenVPN 3 device {name:?}: {e}"),
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err(last)
    }

    /// Wait until `cancel` or the session ends; returns why it ended.
    pub fn wait(&self, cancel: &AtomicBool, log: &dyn Fn(String)) -> &'static str {
        let mut last = String::new();
        while !cancel.load(Ordering::SeqCst) {
            match self.status() {
                Ok((CONNECTION, FAILED | DISCONNECTED | DONE | AUTH_FAILED, msg)) => {
                    log(format!("OpenVPN 3: {msg}"));
                    return "the gateway ended the connection";
                }
                // a reconnect needs the username and token again, and the token can't be reused: end the session
                // instead of showing Connected while it stalls
                Ok((CONNECTION, RECONNECTING, msg)) | Ok((_, REQUIRE_USER, msg)) => {
                    log(format!("OpenVPN 3: {msg}"));
                    return "the connection was interrupted; connect again to sign in anew";
                }
                Ok((_, _, msg)) if msg != last => {
                    log(format!("OpenVPN 3: {msg}"));
                    last = msg;
                }
                Ok(_) => {}
                Err(e) => {
                    log(format!("OpenVPN 3: {e}"));
                    return "the OpenVPN 3 session ended";
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        "disconnect requested"
    }
}

/// Disconnecting stops the backend and removes the session (and its single-use config).
impl Drop for Session<'_> {
    fn drop(&mut self) {
        // a session that failed to connect may be gone already: don't wait for it to appear
        self.retry.set(None);
        let _ = self.method::<()>("Disconnect", &());
    }
}

/// One method call. With `retry`: the services are D-Bus-activated and own their name before they export the object,
/// so "does not exist" is retried for up to 10 s, until `retry` is set (cancelled). Without, it fails at once: a session
/// that's gone stays gone.
#[allow(clippy::too_many_arguments)]
fn call<R: DeserializeOwned + zbus::zvariant::Type>(
    bus: &Connection,
    dest: &str,
    path: &str,
    iface: &str,
    method: &str,
    body: &(impl serde::Serialize + DynamicType),
    retry: Option<&AtomicBool>,
) -> Result<R, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = bus
            .call_method(Some(dest), path, Some(iface), method, body)
            .and_then(|m| m.body().deserialize::<R>());
        match r {
            Ok(v) => return Ok(v),
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown" =>
            {
                return Err(install_hint());
            }
            Err(e)
                if e.to_string().contains("does not exist")
                    && retry.is_some_and(|c| !c.load(Ordering::SeqCst))
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(format!("OpenVPN 3 {method}: {e}")),
        }
    }
}
