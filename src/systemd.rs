//! Cleanup that doesn't depend on the backend: if it dies without tearing down (a crash, a SIGKILL, the OOM killer),
//! systemd removes the routes, the xfrm interface and the IPv6 block, so the machine's own network works again.
//! The backend puts itself in the transient scope `archway-vpn.scope` (charon, started later, joins it) and starts
//! the guard service `archway-vpn-cleanup.service`, bound to that scope. When the scope empties, systemd stops the
//! guard, and the guard's `ExecStop` runs `ip`. systemd never runs this program itself, so SELinux doesn't stop it
//! from cleaning up after a binary in a home folder. Root may start units over D-Bus without asking polkit.
//!
//! The guard removes the interface by name, so after a normal disconnect (the backend already removed it) it would
//! also remove an interface another program created under that name in the moment between the two. Connect refuses
//! a name that's taken (`netlink::ensure_free`), which leaves only that moment.

use crate::net::IfName;
use crate::netlink::RT_PROTO;
use std::path::Path;
use std::time::{Duration, Instant};
use zbus::zvariant::{OwnedObjectPath, Value};

const SCOPE: &str = "archway-vpn.scope";
const GUARD: &str = "archway-vpn-cleanup.service";
const IP_PATHS: [&str; 4] = ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"];

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait Manager {
    fn start_transient_unit(
        &self,
        name: &str,
        mode: &str,
        properties: &[(&str, Value<'_>)],
        aux: &[(&str, &[(&str, Value<'_>)])],
    ) -> zbus::Result<OwnedObjectPath>;
}

/// The guard's teardown, as `ip` commands: everything `netlink::purge` removes, with the interface by name. Each may
/// fail (after a normal disconnect there is nothing left), so failures are ignored.
fn teardown(ip: &str, ifname: &IfName) -> Vec<(String, Vec<String>, bool)> {
    let proto = RT_PROTO.to_string();
    [
        vec!["route", "flush", "table", "all", "proto", &proto],
        vec!["-6", "route", "flush", "table", "all", "proto", &proto],
        vec!["link", "del", &ifname.to_string()],
    ]
    .into_iter()
    .map(|args| {
        let argv = std::iter::once(ip).chain(args).map(String::from).collect();
        (ip.to_string(), argv, true)
    })
    .collect()
}

/// Put this process in `SCOPE` and arm the guard that cleans up `ifname` and our routes once the scope is empty.
pub fn guard(ifname: &IfName) -> Result<(), String> {
    let ip = IP_PATHS
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or("the `ip` program (iproute2) isn't installed; it removes the VPN's routes if Archway stops unexpectedly")?;
    let conn = zbus::blocking::Connection::system().map_err(|e| format!("system D-Bus: {e}"))?;
    let m = ManagerProxyBlocking::new(&conn).map_err(|e| format!("systemd: {e}"))?;
    let start = |name: &str, props: &[(&str, Value<'_>)]| {
        m.start_transient_unit(name, "fail", props, &[])
            .map(drop)
            .map_err(|e| match e {
                zbus::Error::MethodError(n, ..)
                    if n.as_str() == "org.freedesktop.systemd1.UnitExists" =>
                {
                    "the previous VPN session is still being cleaned up; connect again in a moment"
                        .to_string()
                }
                e => format!("cannot start {name}: {e}"),
            })
    };
    let scope = [
        ("Description", Value::new("Archway VPN backend")),
        ("PIDs", Value::new(vec![std::process::id()])),
        // a scope that failed must not block the next connect
        ("CollectMode", Value::new("inactive-or-failed")),
    ];
    // right after a disconnect the previous scope stays until its guard has cleaned up: give it a few seconds
    let t0 = Instant::now();
    while let Err(e) = start(SCOPE, &scope) {
        if t0.elapsed() > Duration::from_secs(5) {
            return Err(e);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    start(
        GUARD,
        &[
            ("Description", Value::new("Archway VPN cleanup")),
            ("Type", Value::new("oneshot")),
            ("RemainAfterExit", Value::new(true)),
            ("ExecStop", Value::new(teardown(ip, ifname))),
            ("BindsTo", Value::new(vec![SCOPE])),
            ("After", Value::new(vec![SCOPE])),
            ("CollectMode", Value::new("inactive-or-failed")),
        ],
    )?;
    // systemd only queued the jobs: make sure this process really is in the scope before relying on the guard
    let t0 = Instant::now();
    while !in_scope() {
        if t0.elapsed() > Duration::from_secs(5) {
            return Err(format!("systemd didn't move the VPN backend into {SCOPE}"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn in_scope() -> bool {
    std::fs::read_to_string("/proc/self/cgroup")
        .is_ok_and(|c| c.lines().any(|l| l.ends_with(&format!("/{SCOPE}"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teardown_removes_what_the_backend_adds() {
        let t = teardown("/usr/sbin/ip", &"archway0".parse().unwrap());
        let argv: Vec<String> = t.iter().map(|(_, a, _)| a.join(" ")).collect();
        assert_eq!(
            argv,
            [
                "/usr/sbin/ip route flush table all proto 233",
                "/usr/sbin/ip -6 route flush table all proto 233",
                "/usr/sbin/ip link del archway0",
            ]
        );
        assert!(
            t.iter()
                .all(|(p, _, ignore)| p == "/usr/sbin/ip" && *ignore)
        );
    }
}
