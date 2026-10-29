# Fuzzing Archway

libFuzzer targets (cargo-fuzz) for everything that parses bytes from outside the process: charon's VICI socket, the
FortiGate's and AIA servers' HTTP answers and certificates, shared profile files of every connection type, imported
Azure VPN profiles, the GUI ↔ backend JSON lines, the browser's callback request, and Microsoft Entra's token answer. The app's `fuzzing` feature builds `src/lib.rs`, which exposes those modules to the
targets here; the app itself never uses it.

## Setup

```bash
rustup toolchain install nightly --profile minimal
rustup component add rust-src --toolchain nightly   # cargo-fuzz builds std with sanitizers
cargo install cargo-fuzz
```

libFuzzer's runtime is C++, so it needs a C++ compiler and libstdc++ to link against: `sudo dnf install gcc-c++`
(Fedora) or `sudo apt install g++` (Debian, Ubuntu). Without root, `pixi global install gxx` works too, then
`export CXX=~/.pixi/bin/g++ RUSTFLAGS="-L $HOME/.pixi/envs/gxx/lib"`.

## Run

From this directory (`fuzz/`). Keep the build output off tmpfs: pass a target dir on disk.

```bash
export FUZZ_TARGET_DIR=~/.cache/archway-fuzz/target
cargo +nightly fuzz list
cargo +nightly fuzz run profile_toml --target-dir $FUZZ_TARGET_DIR -- -max_total_time=300 -dict=dict/toml.dict
```

Each target has a seed corpus in `corpus/<target>/` (checked in) and a dictionary that fits it:

| Target | Input | Dictionary |
|---|---|---|
| `vici_packet` | one VICI packet payload from charon, decoded as every message shape the backend reads | `dict/vici.dict` |
| `vici_session` | a whole session's worth of charon replies on a socket pair, through `check_plugins`, `connect`, `established`, events | `dict/vici.dict` |
| `http_response` | an HTTP response from the SSO port or an AIA server: header split, chunked decoding, redirect extraction | `dict/http.dict` |
| `x509_blob` | DER/PEM/PKCS#7 from an AIA server, and the AIA URL lookup on a certificate | – |
| `profile_toml` | a shared profile file of either type (the `type` key); round-trips what Save writes, the FortiGate backend request and the Azure OpenVPN config built from it | `dict/toml.dict` |
| `backend_request` | the JSON line the root backend reads first, on to the charon config and `load-conn` message | `dict/json.dict` |
| `backend_event` | a backend stdout line as the GUI reads it, and `Diag::parse` | `dict/json.dict` |
| `saml_callback` | the HTTP request on the local sign-in callback listener (FortiGate SAML and Entra) | `dict/http.dict` |
| `net_types` | every checked value type: parse, print, parse again; the Azure gateway's certificate name and the tenant host allowlist | – |
| `azure_profile` | the Azure portal zip or the `azurevpnconfig.xml` in it, picked for import: the zip reader (the entry names it accepts, an entry past the size cap), the typed fields, Save-and-load of the result, and the OpenVPN config built from it having exactly the template's lines | `dict/xml.dict` |
| `entra_answer` | what comes back from the Entra sign-in: the browser's callback query (code or error, only with our state) and the token endpoint's JSON | `dict/http.dict` |

Run them all for five minutes each:

```bash
for t in $(cargo +nightly fuzz list); do
    d=dict/http.dict; case $t in vici_*) d=dict/vici.dict;; profile_toml) d=dict/toml.dict;; backend_*) d=dict/json.dict;; azure_profile) d=dict/xml.dict;; x509_blob|net_types) d=;; esac
    cargo +nightly fuzz run $t --target-dir $FUZZ_TARGET_DIR -- -max_total_time=300 -max_len=16384 ${d:+-dict=$d}
done
```

## Regressions

`regressions/<target>/` holds the inputs that crashed a target before the bug was fixed. Run them after changing the
parsers:

```bash
for f in regressions/*/*; do
    cargo +nightly fuzz run "$(basename "$(dirname "$f")")" --target-dir $FUZZ_TARGET_DIR "$f"
done
```

The same cases are unit tests in the app (`cargo test`), so they're checked without the fuzzer too.

## Crashes

A crash lands in `artifacts/<target>/`. Reproduce and shrink it with

```bash
cargo +nightly fuzz run <target> --target-dir $FUZZ_TARGET_DIR artifacts/<target>/crash-...
cargo +nightly fuzz tmin <target> --target-dir $FUZZ_TARGET_DIR artifacts/<target>/crash-...
```

Coverage of a corpus (needs `llvm-tools-preview` on nightly):

```bash
cargo +nightly fuzz coverage <target> --target-dir $FUZZ_TARGET_DIR
```

