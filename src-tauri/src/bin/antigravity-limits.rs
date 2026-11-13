//! antigravity-limits — companion tool, deliberately NOT part of the scan.
//!
//! Antigravity's Limit state lives only with Google, so a live gauge means
//! presenting the sign-in Antigravity already stores to `cloudcode-pa`.
//! ADR-0019 moves that fetch out of the app for the same reason as the other
//! Companions: the always-running process provably never touches a vendor
//! credential, checkable by grep rather than promised by code review.
//!
//! **This Companion differs from `claude-limits` and `codex-limits` in exactly
//! one way, and it is deliberate.** Those two do not even model a refresh
//! token — the cheapest possible guarantee that they never spend one. This one
//! does, because Google's access tokens die in about an hour, so under that
//! literal rule an Antigravity card could show a figure only within an hour of
//! the person last running the tool. [ADR-0020] re-derives the bound from the
//! property it was protecting — never corrupt the Source's own session — and
//! finds the Google refresh grant leaves it intact: the response carries no
//! replacement refresh token, and Google's grant-eviction cap counts
//! *authorization* grants, which a refresh never creates, so no number of
//! exchanges can evict Antigravity's own token.
//!
//! The bounds that come with that permission, all load-bearing:
//!
//! 1. The exchange goes to `https://oauth2.googleapis.com/token` and nowhere
//!    else, and the Keychain item is **never written**. A stored access token
//!    that has not expired is used as-is; the exchange happens only on expiry.
//! 2. **No cache.** The minted token lives only in this process's memory —
//!    never a file, never the Keychain — so "TokenLedger never writes a Google
//!    token" stays greppable rather than promised. (If a cache is ever added it
//!    must bind to a one-way fingerprint of the refresh credential, or a logout
//!    or account switch could serve the previous account's figures.)
//! 3. The client id/secret pair identifies *Antigravity*, not us. Google's
//!    installed-app model ships both halves in every copy of each client: they
//!    are public identifiers, not keys. The id is hardcoded because the scan
//!    below needs a fixed thing to anchor on; the secret is read out of
//!    Antigravity's own installed client at run time, so this repository holds
//!    no copy of a vendor identifier that can go stale. Either one missing
//!    means no exchange, and the card degrades to signed-out pointing at
//!    Antigravity (ADR-0019 bound 4).
//! 4. ADR-0019 bounds 2–4 stand. Bound 3's floor between calls is also an
//!    obligation to Antigravity's own session, not only a consent rule: the
//!    refresh grant is rate-limited per client, and this Companion shares
//!    Antigravity's client id with Antigravity itself.
//!
//! [ADR-0020]: ../../../docs/adr/0020-a-companion-may-exchange-a-google-refresh-token.md

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{json, Value};

use tokenledger_lib::limits_artifact::{
    self, LimitState, LimitStateWindow, LimitsExport, WindowExport, NOT_SIGNED_IN, STATE_SCHEMA,
};

/// The desktop app's Cloud Code endpoint. The other endpoint can return a
/// different Gemini balance for the same sign-in, so it cannot stand in for it.
const CLOUD_CODE_HOST: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const VERIFIED_HUB_VERSION: &str = "2.35.1";

/// Antigravity's own installed-app client, verified verbatim in its
/// `language_server` binary. Presenting it means presenting ourselves to Google
/// as Antigravity — the same posture as `claude-limits` presenting Claude
/// Code's own token, which ADR-0019 already accepts on this route.
const CLIENT_ID: &str = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
/// How Google spells the other half of an installed-app pair.
const SECRET_PREFIX: &[u8] = b"GOCSPX-";
const SECRET_SUFFIX_LEN: usize = 28;

/// Enough of the id to anchor the secret scan on — the account part, taken off
/// `CLIENT_ID` rather than written out again, since a second copy could drift
/// from the first. The `.apps.googleusercontent.com` tail is stored separately
/// in some string tables, so anchoring on the whole id would miss.
fn id_anchor() -> &'static [u8] {
    CLIENT_ID
        .split('.')
        .next()
        .unwrap_or(CLIENT_ID)
        .as_bytes()
}

/// The Keychain item Antigravity writes. Here `-a` **is** used, unlike Claude's
/// item: the account is the literal string `antigravity` rather than a user name
/// (so the `@`-in-account bug that forced `-a` off Claude's lookup cannot
/// arise), and the service name `gemini` is generic enough that other Google
/// tooling could plausibly claim it.
const KEYCHAIN_SERVICE: &str = "gemini";
const KEYCHAIN_ACCOUNT: &str = "antigravity";
/// The wrapper `go-keyring` puts around a stored value. Antigravity's own
/// string, not a convention invented here.
const ENVELOPE_PREFIX: &str = "go-keyring-base64:";

/// `errSecItemNotFound` — the honest "not signed in". Every other non-zero exit
/// is a failure and must never be reported as an absence.
const EXIT_ITEM_NOT_FOUND: i32 = 44;

fn main() {
    match run() {
        // stdout echoes the Artifact for a hand run and for inspection. It is not
        // the ingest path — the app reads the file, per ADR-0019.
        Ok(report) => println!("{report}"),
        Err(err) => {
            eprintln!("antigravity-limits: {err}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String, String> {
    let credential = credential()?;
    let fetched_at = now();
    let access_token = access_token(&credential, fetched_at)?;
    let user_agent = hub_user_agent(desktop_version().as_deref());

    // One call, two needs: the project the summary request names, and the plan
    // label.
    let assist = post(&access_token, "loadCodeAssist", &json!({}), &user_agent)?;

    // The descriptor marks `project` REQUIRED, so it is passed whenever the
    // vendor named one. When it does not — an individual-tier account may have
    // no companion project at all — the field is **omitted rather than sent
    // empty**. An empty string is a value the server would be entitled to answer
    // about, which is the silent-fallthrough this argument exists to prevent; an
    // absent field lets the server apply its own default, which is what the
    // prior art relies on. Refusing outright would be worse than either: it
    // would deny a card to an account whose Limits the server may answer for
    // perfectly well.
    let project = wire_field(&assist, "cloudaicompanionProject")
        .and_then(|p| p.as_str())
        .filter(|p| !p.trim().is_empty());
    let request = match project {
        Some(project) => json!({ "project": project }),
        None => json!({}),
    };
    let summary = post(&access_token, "retrieveUserQuotaSummary", &request, &user_agent);

    if std::env::args().skip(1).any(|a| a == "--shape") {
        return Ok(diagnose(&access_token, &user_agent, &assist, &summary));
    }

    let (windows, undated) = windows(&summary?)?;
    let export = LimitsExport {
        schema: limits_artifact::SCHEMA,
        source: "antigravity".to_string(),
        fetched_at,
        plan: plan(&assist),
        windows,
        // Antigravity is not in the estimate map: nothing has established
        // what each of its pools meters, so it claims nothing.
        ..Default::default()
    };

    // A failed write is a failed run: the Artifact is how the reading reaches
    // the app at all, so exiting 0 here would report success having delivered
    // nothing, and the card would show an absence rather than the cause.
    if let Some(dir) = std::env::var_os("TOKENLEDGER_LIMITS_DIR") {
        let dir = PathBuf::from(dir);
        limits_artifact::write(&dir, &export)
            .map_err(|err| format!("could not write the export: {err}"))?;
        // Replace the previous snapshot even when every bucket now has a reset.
        limits_artifact::write_state(
            &dir,
            &LimitState {
                schema: STATE_SCHEMA,
                source: export.source.clone(),
                via: "live".to_string(),
                observed_at: fetched_at,
                windows: undated,
            },
        )
        .map_err(|err| format!("could not write the current limits: {err}"))?;
    }
    serde_json::to_string(&export).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// The credential document
// ---------------------------------------------------------------------------

/// What the stored document carries that a Limits fetch needs. `refresh_token`
/// is modelled here — and only here among the Companions — under ADR-0020.
struct Credential {
    access_token: String,
    /// Epoch seconds. The stored token is presented as-is while this is in the
    /// future; only past it is anything exchanged.
    expiry: i64,
    refresh_token: String,
}

fn credential() -> Result<Credential, String> {
    parse_envelope(&keystore_read()?)
}

/// The stored value, or the classified reason it could not be had. `Ok` carries
/// the raw envelope; the item's absence is the one case that reads as an
/// absence rather than a failure.
fn keystore_read() -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        // go-keyring targets Secret Service and WinCred elsewhere, but that has
        // never been verified for this item, and guessing at a store would
        // report the wrong thing. Say what is true.
        return Err(format!(
            "{NOT_SIGNED_IN}: reading Antigravity's sign-in is only supported on macOS today"
        ));
    }
    let output = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
        ])
        .output()
        .map_err(|e| format!("could not run the credential reader: {e}"))?;

    if output.status.success() {
        // Never logged, here or anywhere.
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }
    if output.status.code() == Some(EXIT_ITEM_NOT_FOUND) {
        return Err(format!(
            "{NOT_SIGNED_IN}: no Antigravity sign-in found on this computer"
        ));
    }

    // The same stderr taxonomy `claude-limits` classifies by, so a locked
    // keystore says it is locked rather than being reported as an absence.
    // ponytail: deliberately duplicated rather than shared. The one library both
    // Companions already import is compiled into the app, and ADR-0019's whole
    // guarantee is that the always-running process never touches credential
    // machinery — checkable by grep. Hoisting this there would put keystore
    // vocabulary in the app to save twenty lines in two tools that are separate
    // processes on purpose.
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    let reason = if stderr.contains("locked") || stderr.contains("unlock") {
        "the login keystore is locked — unlock it and check again"
    } else if stderr.contains("interaction is not allowed") || stderr.contains("no user interaction")
    {
        "the credential store refused to answer without user interaction"
    } else if stderr.contains("cancel") {
        "the credential read was cancelled"
    } else if stderr.contains("authorization")
        || stderr.contains("authentication")
        || stderr.contains("name or passphrase")
    {
        "the credential store refused authorization"
    } else {
        "the credential store could not be read"
    };
    Err(format!(
        "{reason} (security find-generic-password exited {})",
        output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "abnormally".into()),
    ))
}

/// `go-keyring-base64:<base64 JSON>` → the token triple. A malformed envelope is
/// a **failure**, never an absence: telling someone they are not signed in when
/// the document was merely unreadable sends them to redo a login they have.
fn parse_envelope(raw: &str) -> Result<Credential, String> {
    let unreadable = || "the stored Antigravity sign-in could not be read".to_string();
    let encoded = raw.strip_prefix(ENVELOPE_PREFIX).ok_or_else(unreadable)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| unreadable())?;
    let v: Value = serde_json::from_slice(&decoded).map_err(|_| unreadable())?;

    let token = v
        .get("token")
        .and_then(Value::as_object)
        .ok_or_else(unreadable)?;
    let string = |key: &str| {
        token
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
    };
    let access_token = string("access_token");
    let refresh_token = string("refresh_token");
    if access_token.is_empty() && refresh_token.is_empty() {
        return Err(format!(
            "{NOT_SIGNED_IN}: the stored sign-in carries no token"
        ));
    }
    Ok(Credential {
        access_token: access_token.to_string(),
        // Go marshals this in the machine's own location, so the offset is
        // load-bearing: read as UTC, a +08:00 stamp would look hours fresher
        // than it is and a dead token would be presented as live.
        expiry: token
            .get("expiry")
            .and_then(|e| e.as_str())
            .and_then(rfc3339_to_epoch)
            .unwrap_or(0),
        refresh_token: refresh_token.to_string(),
    })
}

fn rfc3339_to_epoch(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.timestamp())
}

// ---------------------------------------------------------------------------
// The token
// ---------------------------------------------------------------------------

/// Whether the stored pass still has life in it. A minute of headroom: one
/// expiring while the request is in flight would 401, and the exchange is the
/// cheaper branch to take early. Split out from the fetch so the gate itself is
/// testable — everything past it needs Google.
fn stored_pass_holds(credential: &Credential, now: i64) -> bool {
    credential.expiry > now + 60 && !credential.access_token.is_empty()
}

/// The stored access token while it lives, a freshly minted one after that.
/// Nothing is written anywhere in either case (ADR-0020 bounds 1 and 2).
fn access_token(credential: &Credential, now: i64) -> Result<String, String> {
    if stored_pass_holds(credential, now) {
        return Ok(credential.access_token.clone());
    }
    if credential.refresh_token.is_empty() {
        return Err(format!(
            "{NOT_SIGNED_IN}: the stored Antigravity sign-in has expired — open Antigravity once to renew it"
        ));
    }
    exchange(&credential.refresh_token)
}

fn exchange(refresh_token: &str) -> Result<String, String> {
    let client_secret = client_secret()?;
    let response = ureq::post(TOKEN_URL)
        .timeout(Duration::from_secs(15))
        .send_form(&[
            ("client_id", CLIENT_ID),
            ("client_secret", &client_secret),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ]);
    let body: Value = match response {
        Ok(response) => response
            .into_string()
            .map_err(|e| e.to_string())
            .and_then(|body| serde_json::from_str(&body).map_err(|e| e.to_string()))
            .map_err(|e| format!("the sign-in service's answer could not be read: {e}"))?,
        Err(ureq::Error::Status(code, response)) => {
            let body = response
                .into_string()
                .ok()
                .and_then(|body| serde_json::from_str(&body).ok())
                .unwrap_or(Value::Null);
            return Err(refresh_failure(code, &body));
        }
        Err(err) => return Err(format!("could not reach the sign-in service: {err}")),
    };
    // The response is expected to carry no replacement refresh token, and there
    // is no field here for one if it did: what is minted is used once, in this
    // process, and discarded when it exits.
    body.get("access_token")
        .and_then(|t| t.as_str())
        .filter(|t| !t.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| "the sign-in service returned no access pass".to_string())
}

fn refresh_failure(code: u16, body: &Value) -> String {
    match body.get("error").and_then(Value::as_str) {
        Some("invalid_grant") if code == 400 => format!(
            "{NOT_SIGNED_IN}: Google would not renew the saved Antigravity sign-in — open Antigravity once to sign in again"
        ),
        Some(reason @ ("invalid_client" | "unauthorized_client" | "deleted_client")) => {
            format!("Google refused the Antigravity OAuth client ({code}, {reason})")
        }
        _ => format!("the sign-in service answered {code}"),
    }
}

// ---------------------------------------------------------------------------
// The vendor's own half of the pair
// ---------------------------------------------------------------------------

/// The client secret, read out of Antigravity's installed client (ADR-0020
/// bound 3). Only ever called on the exchange path, so a live stored pass costs
/// nothing, and the ≥60s floor already bounds how often it runs.
///
/// Not cached to disk and not carried in this repository: it is the vendor's
/// identifier, it can rotate, and a copy here would go stale silently — signing
/// every user out until somebody noticed and edited a constant.
fn client_secret() -> Result<String, String> {
    let path = language_server().ok_or_else(|| {
        "Antigravity is not installed where its sign-in could be renewed".to_string()
    })?;
    // ponytail: reads the whole image (~127MB) and scans it linearly, in a
    // process that exits moments later. Chunk it or memory-map it if the spike
    // or the ~1s ever shows up beside the network call it precedes.
    let image = std::fs::read(&path)
        .map_err(|err| format!("could not read Antigravity's client: {err}"))?;
    secret_in(&image).ok_or_else(|| {
        "Antigravity's installed client carries no sign-in pair this version knows".to_string()
    })
}

/// Where Antigravity keeps the client. Both halves of the pair ship inside it —
/// which is where they came from in the first place.
fn language_server() -> Option<PathBuf> {
    desktop_bundles()
        .map(|bundle| bundle.join("Contents/Resources/bin/language_server"))
        .find(|path| path.is_file())
}

fn desktop_bundles() -> impl Iterator<Item = PathBuf> {
    std::iter::once(PathBuf::from("/Applications/Antigravity.app")).chain(
        dirs::home_dir().map(|home| home.join("Applications/Antigravity.app")),
    )
}

fn desktop_version() -> Option<String> {
    let plist = desktop_bundles()
        .map(|bundle| bundle.join("Contents/Info.plist"))
        .find(|path| path.is_file())?;
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", "CFBundleShortVersionString", "raw"])
        .arg(plist)
        .output()
        .ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Google sends only third-party buckets when the desktop hub version is absent.
fn hub_user_agent(version: Option<&str>) -> String {
    let version = version.map(str::trim).filter(|version| {
        version.len() <= 32
            && version.split('.').count() == 3
            && version.split('.').all(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            })
    });
    format!("antigravity/hub/{}", version.unwrap_or(VERIFIED_HUB_VERSION))
}

/// The 2.35 desktop OAuth function references the client ID and the secret
/// immediately after `:generateContent` in its Go string table. A nearby MCP
/// client has its own secret, so proximity alone picks the wrong pair there.
/// Keep the proximity lookup for older builds with a different string layout.
fn secret_in(image: &[u8]) -> Option<String> {
    let anchor = find(image, id_anchor())?;
    let mut nearest: Option<(usize, String)> = None;
    let mut at = 0;
    while let Some(found) = find(&image[at..], SECRET_PREFIX) {
        let start = at + found;
        if let Some(secret) = secret_at(image, start) {
            let tail = start + secret.len();
            if image[..start].ends_with(b":generateContent")
                && find(&image[tail..image.len().min(tail + 45)], b"sandbox.googleapis.com").is_some()
            {
                return Some(secret);
            }
            let closer = nearest
                .as_ref()
                .is_none_or(|(best, _)| start.abs_diff(anchor) < best.abs_diff(anchor));
            if closer {
                nearest = Some((start, secret));
            }
        }
        at = start + SECRET_PREFIX.len();
    }
    nearest.map(|(_, secret)| secret)
}

/// Go packs adjacent strings together without a terminator. Read only the
/// 28-character OAuth client secret suffix, even if the next string starts
/// with characters from the same alphabet.
fn secret_at(image: &[u8], at: usize) -> Option<String> {
    let candidate = image.get(at..at + SECRET_PREFIX.len() + SECRET_SUFFIX_LEN)?;
    let suffix = candidate.strip_prefix(SECRET_PREFIX)?;
    suffix
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        .then(|| String::from_utf8_lossy(candidate).into_owned())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// The fetch
// ---------------------------------------------------------------------------

fn post(
    access_token: &str,
    method: &str,
    body: &Value,
    user_agent: &str,
) -> Result<Value, String> {
    let response = ureq::post(&format!("{CLOUD_CODE_HOST}:{method}"))
        .set("Authorization", &format!("Bearer {access_token}"))
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .set("User-Agent", user_agent)
        .timeout(Duration::from_secs(15))
        .send_string(&body.to_string());
    match response {
        Ok(response) => response
            .into_string()
            .map_err(|e| e.to_string())
            .and_then(|body| serde_json::from_str::<Value>(&body).map_err(|e| e.to_string()))
            .map_err(|e| format!("the vendor's answer could not be read: {e}")),
        // A refusal carries Google's own reason, and throwing it away is how a
        // diagnosable failure becomes "it doesn't work". A 401 answered to ONE
        // method while another succeeds on the same token is not a sign-in
        // problem at all, so the reason is what decides which card to draw.
        Err(ureq::Error::Status(code, response)) => {
            let reason = refusal(response);
            if matches!(code, 401 | 403) && reason.is_empty() {
                return Err(format!(
                    "{NOT_SIGNED_IN}: Google rejected the saved Antigravity sign-in ({code})"
                ));
            }
            Err(format!("the vendor answered {code} to {method}{reason}"))
        }
        Err(err) => Err(format!("could not reach the vendor: {err}")),
    }
}

/// A hand-run dump of the calls that decide whether this account has a reachable
/// Limit surface (#139): the summary RPC the spec chose, and `fetchAvailableModels`,
/// which is what Antigravity's own client actually calls and which the research
/// says embeds a per-model `quota_info`. Each answer's shape, plus every
/// explanation string in full — those are the vendor's public error and tier
/// prose (`reasonMessage`, `message`, `description`), never a credential, and
/// they are the redacted `<str 180>` that `shape` alone hides.
fn diagnose(
    access_token: &str,
    user_agent: &str,
    assist: &Value,
    summary: &Result<Value, String>,
) -> String {
    fn section(title: &str, body: &Value) -> String {
        let prose: String = prose(body).iter().map(|line| format!("  \"{line}\"\n")).collect();
        format!("--- {title} ---\n{}{prose}", limits_artifact::shape(body))
    }
    let mut out = section("loadCodeAssist", assist);
    out.push_str(&match summary {
        Ok(body) => section("retrieveUserQuotaSummary", body),
        Err(err) => format!("--- retrieveUserQuotaSummary ---\n<failed: {err}>\n"),
    });
    out.push_str(&match post(access_token, "fetchAvailableModels", &json!({}), user_agent) {
        Ok(body) => section("fetchAvailableModels", &body),
        Err(err) => format!("--- fetchAvailableModels ---\n<failed: {err}>\n"),
    });
    out
}

/// Every human-readable explanation in a payload, unredacted: the keys Google
/// puts prose under. None is a credential — they are error text and tier names —
/// and the redaction `shape` applies to long strings hides exactly the one
/// (`UNSUPPORTED_CLIENT`'s 180-char reason) that says what the caller lacks.
fn prose(node: &Value) -> Vec<String> {
    fn walk(node: &Value, out: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                for (key, value) in map {
                    match (key.as_str(), value.as_str()) {
                        ("reasonMessage" | "message" | "description", Some(text)) => {
                            out.push(text.to_string())
                        }
                        _ => walk(value, out),
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|value| walk(value, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(node, &mut out);
    out
}

/// Google's own explanation for a refusal — `status`, `message`, and any
/// `details[].reason` — which is structure and prose, never a credential. The
/// message is capped: it is a hint for a card and a bug report, not a log.
fn refusal(response: ureq::Response) -> String {
    let Some(body) = response.into_string().ok() else {
        return String::new();
    };
    let Ok(body) = serde_json::from_str::<Value>(&body) else {
        return String::new();
    };
    let error = body.get("error").unwrap_or(&body);
    let mut parts: Vec<String> = Vec::new();
    if let Some(status) = error.get("status").and_then(|s| s.as_str()) {
        parts.push(status.to_string());
    }
    if let Some(reason) = error
        .pointer("/details/0/reason")
        .and_then(|r| r.as_str())
    {
        parts.push(reason.to_string());
    }
    if let Some(message) = error.get("message").and_then(|m| m.as_str()) {
        parts.push(message.chars().take(200).collect());
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" — {}", parts.join(": "))
    }
}

/// The plan pill. `paidTier` wins over `currentTier`, and the marketing string
/// is cut to one word: a pill reading "Gemini Code Assist in Google One AI Pro"
/// would not fit beside the tool name. The inherited Windsurf
/// `planStatus.planInfo.planName` is deliberately not read — it reads "Pro" for
/// every paid tier.
fn plan(assist: &Value) -> Option<String> {
    let name = ["paidTier", "currentTier"]
        .iter()
        .find_map(|k| assist.pointer(&format!("/{k}/name")).and_then(|n| n.as_str()))?;
    Some(tier_word(name))
}

fn tier_word(name: &str) -> String {
    // "Google AI Pro" → "Pro"; "Gemini Code Assist in Google One AI Pro" → "Pro".
    // The tier word is what follows the last "AI"; anything else is kept whole
    // rather than truncated into something that means less than it said.
    let words: Vec<&str> = name.split_whitespace().collect();
    match words.iter().rposition(|w| w.eq_ignore_ascii_case("AI")) {
        Some(i) if i + 1 < words.len() => words[i + 1..].join(" "),
        _ => name.to_string(),
    }
}

/// A field under either spelling the wire may use. Google's JSON transcoding
/// emits lowerCamelCase by default, which is what the descriptors' `json_name`
/// entries say and what openusage decodes — but the proto field names are
/// snake_case, and a server configured to emit those would otherwise drop every
/// bucket silently and leave an empty card with nothing to diagnose.
fn wire_field<'a>(node: &'a Value, camel: &str) -> Option<&'a Value> {
    node.get(camel).or_else(|| {
        let mut snake = String::with_capacity(camel.len() + 2);
        for c in camel.chars() {
            if c.is_ascii_uppercase() {
                snake.push('_');
                snake.push(c.to_ascii_lowercase());
            } else {
                snake.push(c);
            }
        }
        node.get(&snake)
    })
}

/// Dated buckets become historical Readings. Buckets with a known fraction and
/// no reset are current state, so the card can show them without inventing an epoch.
fn windows(body: &Value) -> Result<(Vec<WindowExport>, Vec<LimitStateWindow>), String> {
    let mut buckets: Vec<_> = body
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| group.get("buckets").and_then(Value::as_array))
        .flatten()
        .filter_map(bucket_window)
        .collect();
    buckets.sort_by(|a, b| (a.window_minutes, &a.key).cmp(&(b.window_minutes, &b.key)));

    if buckets.is_empty() {
        return Err("Google returned no usable Antigravity quota windows".to_string());
    }

    let mut dated = Vec::new();
    let mut undated = Vec::new();
    for bucket in buckets {
        if let Some(resets_at) = bucket.resets_at {
            dated.push(WindowExport {
                key: bucket.key,
                window_minutes: bucket.window_minutes,
                used_pct: bucket.used_pct,
                resets_at,
                ..Default::default()
            });
        } else {
            undated.push(bucket);
        }
    }
    Ok((dated, undated))
}

/// A bucket that carries a remaining *count* (`remainingAmount`) and no
/// fraction: a figure with no denominator, so no bar (a v2 question). Named so
/// the one wire change that would silently empty the card is a tested fact, not
/// just a branch — it is logged, and the log fires exactly when this is true.
fn reports_an_amount(bucket: &Value) -> bool {
    wire_field(bucket, "remainingFraction").and_then(|f| f.as_f64()).is_none()
        && wire_field(bucket, "remainingAmount").is_some()
}

fn bucket_window(bucket: &Value) -> Option<LimitStateWindow> {
    let id = wire_field(bucket, "bucketId").and_then(|b| b.as_str())?;
    if id.len() > 128
        || !id.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return None;
    }
    if wire_field(bucket, "disabled").and_then(|d| d.as_bool()) == Some(true) {
        return None;
    }
    let Some(remaining) = wire_field(bucket, "remainingFraction").and_then(|f| f.as_f64()) else {
        // The one wire change that would silently empty the card, so it is said
        // out loud rather than dropped: a count with no denominator cannot be a
        // bar, and inventing one would be worse than the blank.
        if reports_an_amount(bucket) {
            eprintln!(
                "antigravity-limits: bucket {id} reports a remaining amount rather than a fraction — no bar can be drawn from a count with no total"
            );
        }
        return None;
    };
    if !(0.0..=1.0).contains(&remaining) {
        return None;
    }
    let resets_at = match wire_field(bucket, "resetTime") {
        None | Some(Value::Null) => None,
        Some(value) => Some(rfc3339_to_epoch(value.as_str()?)?),
    };

    // Preserve the full pool identity so a dedicated Gemini model's quota
    // remains distinct from the shared Gemini quota. A new cadence can still
    // report a balance without an assumed duration.
    let (key, window_minutes) = if let Some(pool) = id.strip_suffix("-5h") {
        (format!("{pool}:w300"), Some(300))
    } else if let Some(pool) = id.strip_suffix("-weekly") {
        (format!("{pool}:w10080"), Some(10_080))
    } else {
        let duration = match wire_field(bucket, "window").and_then(Value::as_str) {
            Some("5h") => Some(300),
            Some("weekly") => Some(10_080),
            _ => None,
        };
        (duration.map_or_else(|| id.to_string(), |minutes| format!("{id}:w{minutes}")), duration)
    };

    Some(LimitStateWindow {
        key,
        window_minutes,
        used_pct: ((1.0 - remaining) * 100.0).round(),
        resets_at,
    })
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_desktop_user_agent_carries_the_installed_hub_version() {
        assert_eq!(hub_user_agent(Some(" 2.36.0\n")), "antigravity/hub/2.36.0");
        for missing in [None, Some(""), Some("2.35.1\r\nInvalid"), Some("2.35")] {
            assert_eq!(hub_user_agent(missing), "antigravity/hub/2.35.1");
        }
    }

    // The summary shape as the vendor's own descriptors define it: buckets under
    // `groups[]`, the balance as a *remaining* fraction, and `resetTime` an
    // absolute Timestamp.
    const SUMMARY: &str = r#"{
        "groups": [{
            "displayName": "Model quota",
            "buckets": [
                {"bucketId": "gemini-5h", "displayName": "Gemini 5-hour",
                 "remainingFraction": 0.42, "resetTime": "2026-08-12T15:14:00Z"},
                {"bucketId": "gemini-weekly", "remainingFraction": 0.69,
                 "resetTime": "2026-08-16T02:00:00Z"},
                {"bucketId": "3p-5h", "remainingFraction": 0.88,
                 "resetTime": "2026-08-12T15:14:00Z"},
                {"bucketId": "3p-weekly", "remainingFraction": 0.82,
                 "resetTime": "2026-08-16T02:00:00Z"}
            ]
        }]
    }"#;

    #[test]
    fn four_buckets_become_four_pool_keyed_windows() {
        let (found, undated) = windows(&serde_json::from_str(SUMMARY).unwrap()).unwrap();
        assert!(undated.is_empty());
        assert_eq!(
            found
                .iter()
                .map(|w| (w.key.as_str(), w.window_minutes, w.used_pct))
                .collect::<Vec<_>>(),
            vec![
                // The pool is part of the key: without it the two 5-hour pools
                // would be one row overwriting the other.
                ("3p:w300", Some(300), 12.0),
                ("gemini:w300", Some(300), 58.0),
                ("3p:w10080", Some(10080), 18.0),
                ("gemini:w10080", Some(10080), 31.0),
            ],
        );
        // 2026-08-12T15:14:00Z, the 5-hour pools' shared reset.
        assert_eq!(found[1].resets_at, 1_786_547_640, "resetTime → unix seconds");
    }

    #[test]
    fn the_fraction_is_what_is_left_so_untouched_is_zero_used() {
        // Reading it the other way round prints "100% used" on a fresh account.
        let body: Value = serde_json::from_str(
            r#"{"groups":[{"buckets":[{"bucketId":"gemini-5h","remainingFraction":1.0,
                "resetTime":"2026-08-12T15:14:00Z"}]}]}"#,
        )
        .unwrap();
        assert_eq!(windows(&body).unwrap().0[0].used_pct, 0.0);
    }

    #[test]
    fn a_bucket_this_card_cannot_draw_yields_no_bar() {
        for bucket in [
            r#"{"bucketId":"gemini-5h","remainingFraction":1.1}"#,
            r#"{"bucketId":"gemini-5h","remainingFraction":0.5,"resetTime":"invalid"}"#,
            r#"{"bucketId":"gemini-5h","remainingAmount":"420","resetTime":"2026-08-12T15:14:00Z"}"#,
            r#"{"bucketId":"gemini-5h","remainingFraction":0.5,"disabled":true,"resetTime":"2026-08-12T15:14:00Z"}"#,
            r#"{"bucketId":"ambiguous:id","remainingFraction":0.5,"resetTime":"2026-08-12T15:14:00Z"}"#,
        ] {
            let body: Value =
                serde_json::from_str(&format!(r#"{{"groups":[{{"buckets":[{bucket}]}}]}}"#)).unwrap();
            assert!(windows(&body).is_err(), "{bucket}");
        }
    }

    #[test]
    fn additional_pools_keep_their_own_balances_and_unknown_cadences() {
        let summary = json!({"groups": [{"buckets": [
            {"bucketId": "gemini-weekly", "remainingFraction": 0.83399284, "resetTime": "2026-11-30T15:14:00Z"},
            {"bucketId": "gemini-argon-wtu-weekly", "remainingFraction": 0.45, "resetTime": "2026-11-30T15:14:00Z"},
            {"bucketId": "gemini-image-5h", "remainingFraction": 0.5},
            {"bucketId": "partner-preview", "window": "rolling", "remainingFraction": 0.2}
        ]}]});
        let (dated, undated) = windows(&summary).unwrap();
        assert_eq!(dated.iter().map(|w| (w.key.as_str(), w.used_pct)).collect::<Vec<_>>(),
            vec![("gemini-argon-wtu:w10080", 55.0), ("gemini:w10080", 17.0)]);
        assert_eq!(undated.iter().map(|w| (w.key.as_str(), w.window_minutes)).collect::<Vec<_>>(),
            vec![("partner-preview", None), ("gemini-image:w300", Some(300))]);
    }

    #[test]
    fn buckets_without_reset_times_remain_visible_without_entering_history() {
        let body = json!({"groups": [{"buckets": [
            {"bucketId": "3p-weekly", "remainingFraction": 1.0},
            {"bucketId": "3p-5h", "remainingFraction": 0.75},
            {"bucketId": "gemini-5h", "remainingFraction": 0.5, "resetTime": "2026-08-12T15:14:00Z"}
        ]}]});
        let (dated, undated) = windows(&body).unwrap();
        assert_eq!(dated.len(), 1);
        assert_eq!(dated[0].key, "gemini:w300");
        assert_eq!(
            undated
                .iter()
                .map(|w| (w.key.as_str(), w.used_pct, w.resets_at))
                .collect::<Vec<_>>(),
            vec![("3p:w300", 25.0, None), ("3p:w10080", 0.0, None)]
        );
    }

    #[test]
    fn only_the_amount_bucket_is_flagged_as_a_countable_with_no_denominator() {
        // The spec's one stderr obligation: the remaining-amount case must be
        // recognised distinctly (it is the wire change that would empty the card
        // silently), and none of the other no-bar cases may borrow that note.
        let amount: Value =
            serde_json::from_str(r#"{"bucketId":"gemini-5h","remainingAmount":"420"}"#).unwrap();
        assert!(reports_an_amount(&amount));
        for other in [
            r#"{"bucketId":"gemini-5h","remainingFraction":0.5}"#,
            r#"{"bucketId":"gemini-5h"}"#,
            // A bucket carrying both is a real fraction, not an amount-only figure.
            r#"{"bucketId":"gemini-5h","remainingFraction":0.5,"remainingAmount":"420"}"#,
        ] {
            assert!(!reports_an_amount(&serde_json::from_str(other).unwrap()), "{other}");
        }
    }

    #[test]
    fn the_deprecated_top_level_buckets_are_not_read() {
        // Field 1 is marked deprecated in the descriptor and field 2 (`groups`)
        // is the live one. Reading both would double-count a server that sends
        // both, and the spec asks for the summary shape and nothing else.
        let body: Value = serde_json::from_str(
            r#"{"buckets":[{"bucketId":"gemini-weekly","remainingFraction":0.5,
                "resetTime":"2026-08-16T02:00:00Z"}]}"#,
        )
        .unwrap();
        assert!(windows(&body).is_err());
    }

    #[test]
    fn a_snake_case_payload_reads_the_same_as_a_camel_case_one() {
        // The descriptors' `json_name` entries say camelCase and that is what
        // Google's transcoding emits — but the proto names are snake_case, and
        // the failure mode if the wire ever used them is an empty card with
        // nothing to diagnose. Both spellings are the same bucket.
        let body: Value = serde_json::from_str(
            r#"{"groups":[{"buckets":[{"bucket_id":"gemini-5h","remaining_fraction":0.42,
                "reset_time":"2026-08-12T15:14:00Z"}]}]}"#,
        )
        .unwrap();
        let (found, _) = windows(&body).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key, "gemini:w300");
        assert_eq!(found[0].used_pct, 58.0);
    }

    #[test]
    fn the_envelope_yields_the_token_triple_and_a_malformed_one_is_a_failure() {
        let document = r#"{"token":{"access_token":"ya29-access","token_type":"Bearer",
            "refresh_token":"1//refresh","expiry":"2026-08-12T09:00:00.123456+08:00"},
            "auth_method":"oauth"}"#;
        let envelope = format!(
            "{ENVELOPE_PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(document),
        );
        let Ok(credential) = parse_envelope(&envelope) else {
            panic!("a well-formed envelope must parse");
        };
        assert_eq!(credential.access_token, "ya29-access");
        assert_eq!(credential.refresh_token, "1//refresh");
        // The offset is load-bearing: 09:00+08:00 is 01:00Z, not 09:00Z. Read as
        // UTC, a dead token would look eight hours fresher than it is.
        assert_eq!(credential.expiry, 1_786_496_400);

        // A malformed envelope must NOT borrow the absence prefix — the app
        // classifies on it, and an unreadable document is a failure.
        let non_object_token = base64::engine::general_purpose::STANDARD.encode(br#"{"token":[]}"#);
        for broken in [
            "not-an-envelope",
            "go-keyring-base64:!!!!",
            "go-keyring-base64:e30=",
            &format!("{ENVELOPE_PREFIX}{non_object_token}"),
        ] {
            // `.err()` rather than `expect_err`: `Credential` carries no Debug,
            // so a token can never reach a panic message by accident.
            let err = parse_envelope(broken).err().expect("must not parse");
            assert!(!err.starts_with(NOT_SIGNED_IN), "{broken}: {err}");
        }
    }

    #[test]
    fn a_live_stored_token_is_used_as_is_and_only_an_expired_one_is_exchanged() {
        let credential = |expiry, access: &str| Credential {
            access_token: access.to_string(),
            expiry,
            refresh_token: "1//refresh".to_string(),
        };
        // Comfortably alive: presented as-is, nothing is exchanged and Google is
        // never reached at all (ADR-0020 bound 1).
        assert!(stored_pass_holds(&credential(2_000, "ya29-stored"), 1_000));
        assert_eq!(
            access_token(&credential(2_000, "ya29-stored"), 1_000).as_deref(),
            Ok("ya29-stored"),
        );
        // Expired, and also within the minute of headroom — a pass dying while
        // the request is in flight would come back a 401.
        assert!(!stored_pass_holds(&credential(1_000, "ya29-stored"), 2_000));
        assert!(!stored_pass_holds(&credential(1_030, "ya29-stored"), 1_000));
        // An envelope holding only a refresh token has nothing to present.
        assert!(!stored_pass_holds(&credential(9_999, ""), 1_000));

        // Past it with nothing to exchange, the card says signed out rather than
        // presenting a dead token and reading the 401 back.
        let spent = Credential {
            access_token: "ya29-stored".to_string(),
            expiry: 1_000,
            refresh_token: String::new(),
        };
        let err = access_token(&spent, 2_000).expect_err("must not be usable");
        assert!(err.starts_with(NOT_SIGNED_IN), "{err}");
    }

    #[test]
    fn only_an_invalid_grant_is_reported_as_a_sign_in_failure() {
        assert!(refresh_failure(400, &json!({"error": "invalid_grant"})).starts_with(NOT_SIGNED_IN));
        for (status, error) in [(401, "invalid_client"), (403, "access_denied"), (502, "unknown")] {
            let detail = refresh_failure(status, &json!({
                "error": error,
                "error_description": "sensitive server detail",
            }));
            assert!(!detail.starts_with(NOT_SIGNED_IN));
            assert!(!detail.contains("sensitive server detail"));
        }
        assert!(!refresh_failure(400, &Value::Null).starts_with(NOT_SIGNED_IN));
    }

    // Fabricated stand-ins, built from the real prefix rather than written out
    // as literals — a hand-typed `GOCSPX-…` in this file would read as a leaked
    // secret to every scanner that ever looks at the repository, and would tie
    // the fixtures to a spelling the constant could change out from under.
    fn fake_secret(fill: char) -> String {
        format!("{}{}", std::str::from_utf8(SECRET_PREFIX).unwrap(), fill.to_string().repeat(SECRET_SUFFIX_LEN))
    }

    fn id() -> String {
        String::from_utf8(id_anchor().to_vec()).unwrap()
    }

    // A stand-in for the vendor's client: string-table noise around the two
    // halves of the pair, the way a Go binary carries its constants.
    fn image(body: &str) -> Vec<u8> {
        format!("\0\0some.other.symbol\0{body}\0trailing.noise\0").into_bytes()
    }

    #[test]
    fn the_secret_is_read_out_of_the_vendors_own_client() {
        let secret = fake_secret('a');
        let found = secret_in(&image(&format!("{}.apps.googleusercontent.com\0{secret}", id())));
        assert_eq!(found.as_ref(), Some(&secret));
    }

    #[test]
    fn go_string_table_text_after_the_client_secret_is_excluded() {
        let secret = fake_secret('a');
        let found = secret_in(&image(&format!("{}\0{secret}extraName99", id())));
        assert_eq!(found.as_ref(), Some(&secret));
    }

    #[test]
    fn the_desktop_oauth_pair_wins_over_a_nearer_other_client() {
        let (desktop, other) = (fake_secret('a'), fake_secret('b'));
        let binary = image(&format!(
            ":generateContent{desktop}example-sandbox.googleapis.com\0{other}\0{}",
            id(),
        ));
        assert_eq!(secret_in(&binary).as_deref(), Some(desktop.as_str()));
    }

    #[test]
    fn a_second_google_client_in_the_same_binary_does_not_win() {
        // A build bundling another Google client would otherwise be a coin
        // toss. The pair's halves ship adjacent, so the nearest one is ours —
        // here the far candidate sits first, so position alone would pick wrong.
        let (theirs, ours) = (fake_secret('f'), fake_secret('n'));
        let found = secret_in(&image(&format!(
            "{theirs}{}{}\0{ours}",
            "\0".repeat(32),
            id(),
        )));
        assert_eq!(found.as_ref(), Some(&ours));
    }

    #[test]
    fn a_client_carrying_no_usable_pair_yields_nothing_rather_than_a_guess() {
        // No id, a bare prefix with nothing behind it, and an id with no secret
        // anywhere: each is a client this version cannot renew a sign-in with,
        // and none of them is an excuse to send Google something invented.
        let prefix = std::str::from_utf8(SECRET_PREFIX).unwrap();
        for body in [
            fake_secret('a'),
            format!("{}\0{prefix}", id()),
            format!("{}\0no pair here", id()),
        ] {
            assert_eq!(secret_in(&image(&body)), None, "{body}");
        }
    }

    #[test]
    fn the_plan_pill_prefers_the_paid_tier_and_says_one_word() {
        let assist: Value = serde_json::from_str(
            r#"{"currentTier":{"name":"Google AI Free"},"paidTier":{"name":"Google AI Pro"}}"#,
        )
        .unwrap();
        assert_eq!(plan(&assist).as_deref(), Some("Pro"));

        assert_eq!(tier_word("Gemini Code Assist in Google One AI Ultra"), "Ultra");
        assert_eq!(tier_word("Google AI Ultra Lite"), "Ultra Lite");
        // A name with no tier word in it keeps what the vendor said rather than
        // being truncated into something that means less.
        assert_eq!(tier_word("Enterprise"), "Enterprise");
        assert_eq!(plan(&serde_json::json!({})), None);
    }
}

/// Opt-in, machine-dependent: the scan above against a real installed client,
/// which is the only thing a fixture cannot stand in for. Ignored by default and
/// quiet where Antigravity is not installed, following the same pattern as this
/// crate's other real-data checks.
///
/// `cargo test --release --bin antigravity-limits real_client -- --ignored --nocapture`
///
/// It reports only *whether* a pair was found and how long the scan took —
/// never the pair, which has no business in a terminal or a transcript.
#[cfg(test)]
mod real_client {
    use super::*;

    #[test]
    #[ignore]
    fn the_installed_client_carries_a_pair_this_scan_can_find() {
        let Some(path) = language_server() else {
            println!("no installed client on this machine — nothing to check");
            return;
        };
        let started = std::time::Instant::now();
        let image = std::fs::read(&path).expect("the installed client must be readable");
        let found = secret_in(&image);
        println!(
            "image {} MB · found: {} · {} ms",
            image.len() / 1_000_000,
            found.is_some(),
            started.elapsed().as_millis(),
        );
        assert!(found.is_some(), "the scan found no pair in the installed client");
    }
}
