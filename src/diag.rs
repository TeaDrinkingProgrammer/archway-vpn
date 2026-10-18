//! Errors as the app shows them: rustc-style text in the log (`error: headline` / `note:` / `help:`), and a banner
//! with the same parts. One value, so the two can't drift.


use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct Diag {
    pub level: String,
    pub headline: String,
    pub note: String,
    pub help: String,
}

/// A connect error the user fixes by filling in one field: its banner has a button that goes there.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Fix {
    Gateway,
    Psk,
    Credentials,
}

impl Fix {
    pub fn button(self) -> &'static str {
        match self {
            Fix::Gateway => "Enter Remote Gateway",
            Fix::Psk => "Enter Pre-shared Key",
            Fix::Credentials => "Enter Username and Password",
        }
    }
}

impl Diag {
    pub fn new(level: &str, headline: &str, note: &str, help: &str) -> Self {
        Self { level: level.into(), headline: headline.into(), note: note.into(), help: help.into() }
    }

    /// One diag as `Display` writes it; None for anything else (several joined, or free text).
    pub fn parse(s: &str) -> Option<Self> {
        let mut lines = s.lines();
        let (level, headline) = lines.next()?.split_once(": ")?;
        let note = lines.next()?.strip_prefix("  note: ")?;
        let help = lines.next()?.strip_prefix("  help: ")?;
        lines.next().is_none().then(|| Self::new(level, headline, note, help))
    }

    pub fn fix(&self) -> Option<Fix> {
        match self.headline.as_str() {
            "can't connect without a remote gateway" => Some(Fix::Gateway),
            "can't connect without a pre-shared key" => Some(Fix::Psk),
            "can't connect without a username and password" => Some(Fix::Credentials),
            _ => None,
        }
    }
}

/// `s` with its first letter upper case: a diag headline as a banner title.
pub fn capitalised(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
}

/// `s` capitalised and ending in a full stop: a diag note or help as a banner line.
pub fn sentence(s: &str) -> String {
    let s = capitalised(s.trim());
    if s.ends_with(['.', '!', '?']) { s } else { s + "." }
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}\n  note: {}\n  help: {}", self.level, self.headline, self.note, self.help)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_round_trips() {
        let d = Diag::new("error", "can't connect without a pre-shared key", "the FortiGate proves who it is with it", "enter it under Connection → Pre-shared Key");
        assert_eq!(d.to_string(), "error: can't connect without a pre-shared key\n  note: the FortiGate proves who it is with it\n  help: enter it under Connection → Pre-shared Key");
        assert_eq!(Diag::parse(&d.to_string()), Some(d));
        assert_eq!(Diag::parse("something else"), None);
    }

    #[test]
    fn banner_text_is_capitalised_sentences() {
        let d = Diag::new("error", "can't connect without a remote gateway", "it's the FortiGate's address", "enter it");
        assert_eq!(capitalised(&d.headline), "Can't connect without a remote gateway");
        assert_eq!(sentence(&d.note), "It's the FortiGate's address.");
        assert_eq!(sentence("ends with a stop."), "Ends with a stop.");
    }
}
