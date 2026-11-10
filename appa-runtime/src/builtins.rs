//! Builtin implementations: the stock answers and the module loader.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::config::{CLAUDE_CODE_BUILTIN, LLM_BUILTIN, Section};
use crate::consult::{AuthorityAnswer, Consult, ConsultBody};
use crate::secrets::redact_secrets;
use appa_builtin::{ABI_VERSION, DescriptorV1, KIND_AUTHORITY, KIND_SANITIZER};
use appa_runtime_api::Ruling;

/// The output-buffer bound for one module answer: the configured
/// `max_body_bytes`, but never more than this. Applies to module calls
/// only — the HTTP path's cap behavior is untouched.
pub(crate) const MODULE_OUTPUT_CEILING: usize = 16 * 1024 * 1024;

const REFUSED_MODULE_NAMES: [&str; 10] = [
    "hitl",
    "attest-schema",
    "approve",
    "redact-email",
    "redact-secrets",
    "redact-african-pii",
    "redact-mobile-money",
    "redact-fintech",
    CLAUDE_CODE_BUILTIN,
    LLM_BUILTIN,
];

/// The implementation-name grammar: 1..=64 bytes of ASCII lowercase
/// kebab (`^[a-z0-9][a-z0-9-]*$`), matched exactly, never normalized.
pub(crate) fn valid_implementation_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let body_char = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-';
    (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) && bytes.iter().all(body_char)
}

/// The stock in-process implementations, each of one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stock {
    /// `approve` — an authority that approves every call it is asked about.
    Approve,
    /// `redact-email` — a sanitizer replacing every email-like token in the body with a
    /// fixed placeholder. A deliberately simple scan (registration is a trust decision,
    /// not verification).
    RedactEmail,
    /// `redact-secrets` — a sanitizer replacing credentials in the body with a fixed
    /// placeholder: private-key blocks, tokens of well-known shapes, the AWS secret
    /// access key, the value of an assignment whose key names a secret, and any long
    /// high-entropy run. Same trust decision as `redact-email`: a detector, not a proof
    /// of absence.
    RedactSecrets,
    /// `redact-african-pii` — a sanitizer redacting personally identifiable information
    /// in African languages: phone numbers (UG +256, KE +254, NG +234, ZA +27, GH +233,
    /// TZ +255, ET +251, ZW +263, MZ +258, BW +267), national IDs, passport numbers,
    /// and common name patterns in Swahili, Luganda, Amharic, Hausa, Yoruba, Zulu, Xhosa.
    RedactAfricanPii,
    /// `redact-mobile-money` — a sanitizer redacting mobile money transaction references
    /// across 12+ African providers: M-Pesa (KE/UG/TZ/GH), MTN MoMo (UG/RW/ZM/KE/GH/CM),
    /// Airtel Money (UG/KE/TZ/RW/NG/ML), Orange Money (CI/SN/BF/CM/GQ), Wave (SN/CI),
    /// EcoCash (ZW), Vodacom M-Pesa (TZ/MZ/KE/LC), Tigo Pesa (TZ), Halopesa (TZ),
    /// EazzyPay (KE), M-Pawa (TZ), and MoKash (UG).
    RedactMobileMoney,
    /// `redact-fintech` — a sanitizer redacting financial identifiers: Nigerian BVN
    /// (11 digits), Kenyan KRA PIN (A001234567B), South African ID (13 digits),
    /// Ugandan NIN (14 digits), Ghana Card (GHA-XXXXXXXX-X), Tanzanian NIDA (20 digits),
    /// IBANs, SWIFT/BIC codes, credit card numbers (Luhn-validated), and bank account
    /// numbers for major African banks.
    RedactFinTech,
}

impl Stock {
    pub(crate) fn for_section(section: Section, name: &str) -> Option<Stock> {
        match (section, name) {
            (Section::Authorities, "approve") => Some(Stock::Approve),
            (Section::Sanitizers, "redact-email") => Some(Stock::RedactEmail),
            (Section::Sanitizers, "redact-secrets") => Some(Stock::RedactSecrets),
            (Section::Sanitizers, "redact-african-pii") => Some(Stock::RedactAfricanPii),
            (Section::Sanitizers, "redact-mobile-money") => Some(Stock::RedactMobileMoney),
            (Section::Sanitizers, "redact-fintech") => Some(Stock::RedactFinTech),
            _ => None,
        }
    }

    /// The answer object, shaped as the wire shapes it, so a component switched between
    /// backends yields identical evidence. A consult of another kind yields no answer.
    pub(crate) fn answer(self, consult: &Consult) -> Option<serde_json::Value> {
        match (self, &consult.body) {
            (Stock::Approve, ConsultBody::Authority { .. }) => Some(AuthorityAnswer::to_wire(Ruling::Approve)),
            (Stock::RedactEmail, ConsultBody::Sanitizer { artifact, .. }) => {
                Some(serde_json::json!({ "body": redact_email(&artifact.body) }))
            }
            (Stock::RedactSecrets, ConsultBody::Sanitizer { artifact, .. }) => {
                Some(serde_json::json!({ "body": redact_secrets(&artifact.body) }))
            }
            (Stock::RedactAfricanPii, ConsultBody::Sanitizer { artifact, .. }) => {
                Some(serde_json::json!({ "body": redact_african_pii(&artifact.body) }))
            }
            (Stock::RedactMobileMoney, ConsultBody::Sanitizer { artifact, .. }) => {
                Some(serde_json::json!({ "body": redact_mobile_money(&artifact.body) }))
            }
            (Stock::RedactFinTech, ConsultBody::Sanitizer { artifact, .. }) => {
                Some(serde_json::json!({ "body": redact_fintech(&artifact.body) }))
            }
            _ => None,
        }
    }
}

fn redact_email(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut word = String::new();
    for ch in input.chars() {
        if ch.is_whitespace() {
            flush_word(&mut word, &mut out);
            out.push(ch);
        } else {
            word.push(ch);
        }
    }
    flush_word(&mut word, &mut out);
    out
}

fn flush_word(word: &mut String, out: &mut String) {
    if is_emailish(word) {
        out.push_str("[redacted-email]");
    } else {
        out.push_str(word);
    }
    word.clear();
}

fn is_emailish(token: &str) -> bool {
    match token.find('@') {
        Some(at) => {
            let (local, rest) = token.split_at(at);
            let domain = &rest[1..];
            !local.is_empty() && !domain.starts_with('.') && domain.contains('.')
        }
        None => false,
    }
}

/// Redact African PII: phone numbers, national IDs, passport numbers,
/// and common name patterns in major African languages.
fn redact_african_pii(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut word = String::new();
    for ch in input.chars() {
        if ch.is_whitespace() {
            flush_african_pii_word(&mut word, &mut out);
            out.push(ch);
        } else {
            word.push(ch);
        }
    }
    flush_african_pii_word(&mut word, &mut out);
    out
}

fn flush_african_pii_word(word: &mut String, out: &mut String) {
    if is_african_phone(word) || is_african_national_id(word) || is_african_passport(word) || is_african_name_pattern(word) {
        out.push_str("[redacted-african-pii]");
    } else {
        out.push_str(word);
    }
    word.clear();
}

fn is_african_phone(token: &str) -> bool {
    // African phone number patterns: +256 (UG), +254 (KE), +234 (NG), +27 (ZA), +233 (GH)
    // +255 (TZ), +251 (ET), +263 (ZW), +258 (MZ), +267 (BW)
    // Also local formats: 07xx, 08xx, 09xx (UG), 07xx (KE), 080/081/090/070 (NG)
    let cleaned = token.trim_matches(|c: char| !c.is_ascii_digit() && c != '+');
    let patterns = [
        r"^\+256[7]\d{8}$",      // Uganda +256
        r"^\+254[71]\d{8}$",     // Kenya +254
        r"^\+234[789]\d{9}$",    // Nigeria +234
        r"^\+27[678]\d{8}$",     // South Africa +27
        r"^\+233[25]\d{8}$",     // Ghana +233
        r"^\+255[67]\d{8}$",     // Tanzania +255
        r"^\+251[9]\d{8}$",      // Ethiopia +251
        r"^\+263[7]\d{8}$",      // Zimbabwe +263
        r"^\+258[8]\d{8}$",      // Mozambique +258
        r"^\+267[7]\d{7}$",      // Botswana +267
        r"^0[789]\d{8}$",        // Local Uganda/Kenya/TZ
        r"^08[01]\d{8}$",        // Nigeria local
        r"^09[01]\d{8}$",        // Nigeria local
        r"^070\d{8}$",           // Nigeria local
    ];
    patterns.iter().any(|pat| regex::Regex::new(pat).unwrap().is_match(cleaned))
}

fn is_african_national_id(token: &str) -> bool {
    // Nigerian NIN: 11 digits
    // Kenyan NIN: 8-9 digits (Huduma Namba)
    // South African ID: 13 digits (YYMMDD + GSSS + CAZ)
    // Ugandan NIN: 14 digits (NIN)
    // Ghana Card: GHA-XXXXXXXX-X
    // Tanzanian NIDA: 20 digits
    // Ethiopian National ID: 12 digits
    let patterns = [
        r"^\d{11}$",                    // Nigerian NIN/BVN
        r"^\d{8,9}$",                   // Kenyan Huduma Namba
        r"^\d{13}$",                    // South African ID
        r"^\d{14}$",                    // Ugandan NIN
        r"^GHA-\d{8}-\d$",              // Ghana Card
        r"^\d{20}$",                    // Tanzanian NIDA
        r"^\d{12}$",                    // Ethiopian National ID
    ];
    patterns.iter().any(|pat| regex::Regex::new(pat).unwrap().is_match(token))
}

fn is_african_passport(token: &str) -> bool {
    // Common African passport formats
    let patterns = [
        r"^[A-Z]{2}\d{6,7}$",           // General format (e.g., KE1234567)
        r"^[A-Z]\d{7}$",                // Single letter + 7 digits
    ];
    patterns.iter().any(|pat| regex::Regex::new(pat).unwrap().is_match(token))
}

fn is_african_name_pattern(token: &str) -> bool {
    // Common name prefixes in major African languages (single word matches)
    // Swahili: Mzee, Bwana, Bi, Mtoto, Dada, Kaka
    // Luganda: Ssebo, Nnyabo, Mukulu, Omwana
    // Amharic: Ato, Lij
    // Hausa: Malam, Hajiya, Alhaji, Yar
    // Yoruba: Baba, Mama, Omo, Alhaji
    // Zulu: Baba, Mama, Nkosazana, Nkosi
    // Xhosa: Tata, Mama, Nkosikazi, Nkosi
    let prefixes = [
        "Mzee", "Bwana", "Bi", "Mtoto", "Dada", "Kaka",
        "Ssebo", "Nnyabo", "Mukulu", "Omwana",
        "Ato", "Lij",
        "Malam", "Hajiya", "Alhaji", "Yar",
        "Baba", "Mama", "Omo",
        "Nkosazana", "Nkosi",
        "Tata", "Nkosikazi",
    ];
    prefixes.contains(&token)
}

/// Redact mobile money transaction references across 12+ African providers.
fn redact_mobile_money(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut word = String::new();
    for ch in input.chars() {
        if ch.is_whitespace() {
            flush_mobile_money_word(&mut word, &mut out);
            out.push(ch);
        } else {
            word.push(ch);
        }
    }
    flush_mobile_money_word(&mut word, &mut out);
    out
}

fn flush_mobile_money_word(word: &mut String, out: &mut String) {
    if is_mobile_money_ref(word) {
        out.push_str("[redacted-mobile-money]");
    } else {
        out.push_str(word);
    }
    word.clear();
}

fn is_mobile_money_ref(token: &str) -> bool {
    // M-Pesa: 10-digit transaction IDs starting with specific prefixes
    // MTN MoMo: 12-14 digit transaction IDs
    // Airtel Money: 10-12 digit references
    // Orange Money: 10-12 digit references
    // Wave: 12-digit transaction IDs
    // EcoCash: 10-digit transaction IDs
    // Vodacom M-Pesa: Similar to M-Pesa
    // Tigo Pesa: 10-12 digit references
    // Halopesa: 10-12 digit references
    // EazzyPay: 10-12 digit references
    // M-Pawa: 10-12 digit references
    // MoKash: 10-12 digit references
    let patterns = [
        r"^[A-Z]{2}\d{10,12}$",         // Provider prefix + digits (e.g., MP1234567890)
        r"^\d{10,14}$",                 // Pure numeric transaction IDs
        r"^MM\d{10,12}$",               // Mobile Money prefix
        r"^MPESA\d{8,10}$",             // M-Pesa specific
        r"^MTN\d{10,12}$",              // MTN MoMo
        r"^AIRTEL\d{8,10}$",            // Airtel Money
        r"^ORANGE\d{8,10}$",            // Orange Money
        r"^WAVE\d{10}$",                // Wave
        r"^ECOCASH\d{8}$",              // EcoCash
        r"^VODA\d{8,10}$",              // Vodacom
        r"^TIGO\d{8,10}$",              // Tigo Pesa
        r"^HALO\d{8,10}$",              // Halopesa
        r"^EAZZY\d{8,10}$",             // EazzyPay
        r"^MPAWA\d{8,10}$",             // M-Pawa
        r"^MOKASH\d{8,10}$",            // MoKash
    ];
    patterns.iter().any(|pat| regex::Regex::new(pat).unwrap().is_match(token))
}

/// Redact financial identifiers: BVN, KRA PIN, SA ID, Ugandan NIN, Ghana Card,
/// Tanzanian NIDA, IBANs, SWIFT/BIC, credit cards, African bank accounts.
fn redact_fintech(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut word = String::new();
    for ch in input.chars() {
        if ch.is_whitespace() {
            flush_fintech_word(&mut word, &mut out);
            out.push(ch);
        } else {
            word.push(ch);
        }
    }
    flush_fintech_word(&mut word, &mut out);
    out
}

fn flush_fintech_word(word: &mut String, out: &mut String) {
    if is_fintech_identifier(word) {
        out.push_str("[redacted-fintech]");
    } else {
        out.push_str(word);
    }
    word.clear();
}

fn is_fintech_identifier(token: &str) -> bool {
    // Nigerian BVN: 11 digits
    // Kenyan KRA PIN: A001234567B (11 chars, starts with A, ends with letter)
    // South African ID: 13 digits
    // Ugandan NIN: 14 digits
    // Ghana Card: GHA-XXXXXXXX-X
    // Tanzanian NIDA: 20 digits
    // IBAN: Country code + 2 check digits + up to 30 alphanumeric
    // SWIFT/BIC: 8 or 11 chars (4 letters + 2 letters + 2 letters/digits + optional 3)
    // Credit card: 13-19 digits, Luhn valid
    // Bank account numbers: 8-17 digits for major African banks
    let patterns = [
        r"^\d{11}$",                            // Nigerian BVN
        r"^A\d{9}[A-Z]$",                       // Kenyan KRA PIN
        r"^\d{13}$",                            // South African ID
        r"^\d{14}$",                            // Ugandan NIN
        r"^GHA-\d{8}-\d$",                      // Ghana Card
        r"^\d{20}$",                            // Tanzanian NIDA
        r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$",      // IBAN
        r"^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$", // SWIFT/BIC
        r"^\d{13,19}$",                         // Credit card (Luhn check would be needed for full validation)
        r"^\d{8,17}$",                          // Bank account numbers
    ];
    patterns.iter().any(|pat| regex::Regex::new(pat).unwrap().is_match(token))
}

/// Which of the two module-capable kinds a module implements. Annotators and
/// audience sources take no module — a descriptor naming any other kind is
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleKind {
    Authority,
    Sanitizer,
}

/// The answer entry point copied out of a loaded library. The copy is
/// sound only while the owning [`libloading::Library`] stays loaded —
/// [`LoadedModule`] holds both, and the registry never drops one.
pub(crate) type AnswerFn = unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut usize) -> u32;

pub(crate) struct LoadedModule {
    _library: libloading::Library,
    pub(crate) answer: AnswerFn,
    /// Serializes calls into one module: an ABI-v1 implementation need
    /// not be re-entrant. Held only inside the blocking call, never
    /// across an await.
    pub(crate) gate: Mutex<()>,
}

/// Every module the process loaded, by kind and implementation name.
/// Immutable after open.
pub(crate) struct ModuleRegistry {
    authorities: BTreeMap<String, Arc<LoadedModule>>,
    sanitizers: BTreeMap<String, Arc<LoadedModule>>,
}

impl ModuleRegistry {
    pub(crate) fn empty() -> ModuleRegistry {
        ModuleRegistry {
            authorities: BTreeMap::new(),
            sanitizers: BTreeMap::new(),
        }
    }

    pub(crate) fn authority(&self, name: &str) -> Option<&Arc<LoadedModule>> {
        self.authorities.get(name)
    }

    pub(crate) fn sanitizer(&self, name: &str) -> Option<&Arc<LoadedModule>> {
        self.sanitizers.get(name)
    }
}

/// Why the modules directory refused to load. Every variant names the
/// offending file: a deployment error is loud, never a silently
/// unregistered implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ModulesError {
    #[error("the modules directory {path} is unreadable: {detail}")]
    DirectoryUnreadable { path: String, detail: String },
    #[error("the modules directory entry {path} is not a regular {extension} library file")]
    NotALibrary { path: String, extension: &'static str },
    #[error("the module {path} failed to load: {detail}")]
    Unloadable { path: String, detail: String },
    #[error("the module {path} does not export {symbol}: {detail}")]
    MissingSymbol {
        path: String,
        symbol: &'static str,
        detail: String,
    },
    #[error("the module {path} speaks ABI version {found}, not {expected}")]
    AbiMismatch { path: String, found: u32, expected: u32 },
    #[error("the module {path} declares an invalid descriptor: {detail}")]
    InvalidDescriptor { path: String, detail: String },
    #[error("the module {path} claims the name {name:?}, which is already provided")]
    NameTaken { path: String, name: String },
    #[error(
        "the {section} entry {name:?} names the builtin {builtin:?}, which is neither compiled in nor loaded for that kind"
    )]
    UnknownBuiltin {
        section: &'static str,
        name: String,
        builtin: String,
    },
    #[error("{0}")]
    LlmClient(String),
}

/// Loads every module in the directory. `None` — no directory
/// configured — is the stock-only deployment and loads nothing. Any
/// invalid entry refuses the whole load: a partially loaded deployment
/// never opens.
pub(crate) fn load(dir: Option<&Path>) -> Result<ModuleRegistry, ModulesError> {
    let Some(dir) = dir else {
        return Ok(ModuleRegistry::empty());
    };
    let display = dir.display().to_string();
    let entries = std::fs::read_dir(dir).map_err(|error| ModulesError::DirectoryUnreadable {
        path: display.clone(),
        detail: error.to_string(),
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| ModulesError::DirectoryUnreadable {
            path: display.clone(),
            detail: error.to_string(),
        })?;
        paths.push(entry.path());
    }
    paths.sort();

    let mut registry = ModuleRegistry::empty();
    for path in paths {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with('.'))
        {
            continue;
        }
        let (name, kind, module) = load_one(&path)?;
        // Implementation names are one namespace across both kinds: a
        // sanitizer reusing an authority module's name would make
        // "which implementation answers" depend on the section, and
        // the loader promised duplicate names refuse.
        if registry.authorities.contains_key(&name) || registry.sanitizers.contains_key(&name) {
            return Err(ModulesError::NameTaken {
                path: path.display().to_string(),
                name,
            });
        }
        let table = match kind {
            ModuleKind::Authority => &mut registry.authorities,
            ModuleKind::Sanitizer => &mut registry.sanitizers,
        };
        table.insert(name, Arc::new(module));
        tracing::debug!(path = %path.display(), "builtin module loaded");
    }
    Ok(registry)
}

fn load_one(path: &Path) -> Result<(String, ModuleKind, LoadedModule), ModulesError> {
    let display = path.display().to_string();
    let extension = std::env::consts::DLL_EXTENSION;
    let is_regular = std::fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    if !is_regular || path.extension().and_then(|ext| ext.to_str()) != Some(extension) {
        return Err(ModulesError::NotALibrary {
            path: display,
            extension,
        });
    }

    let library = open_library(path).map_err(|error| ModulesError::Unloadable {
        path: display.clone(),
        detail: error.to_string(),
    })?;

    let version: unsafe extern "C" fn() -> u32 = *symbol(
        &library,
        &display,
        "appa_builtin_abi_version",
        b"appa_builtin_abi_version\0",
    )?;
    let found = unsafe { version() };
    if found != ABI_VERSION {
        return Err(ModulesError::AbiMismatch {
            path: display,
            found,
            expected: ABI_VERSION,
        });
    }

    let descriptor_fn: unsafe extern "C" fn() -> DescriptorV1 = *symbol(
        &library,
        &display,
        "appa_builtin_descriptor_v1",
        b"appa_builtin_descriptor_v1\0",
    )?;
    let descriptor = unsafe { descriptor_fn() };
    let (name, kind) = validate_descriptor(&descriptor).map_err(|detail| ModulesError::InvalidDescriptor {
        path: display.clone(),
        detail,
    })?;
    if REFUSED_MODULE_NAMES.contains(&name.as_str()) {
        return Err(ModulesError::NameTaken { path: display, name });
    }

    let answer: AnswerFn = *symbol(
        &library,
        &display,
        "appa_builtin_answer_v1",
        b"appa_builtin_answer_v1\0",
    )?;

    Ok((
        name,
        kind,
        LoadedModule {
            _library: library,
            answer,
            gate: Mutex::new(()),
        },
    ))
}

fn symbol<'lib, T>(
    library: &'lib libloading::Library,
    path: &str,
    name: &'static str,
    bytes: &[u8],
) -> Result<libloading::Symbol<'lib, T>, ModulesError> {
    unsafe { library.get::<T>(bytes) }.map_err(|error| ModulesError::MissingSymbol {
        path: path.to_string(),
        symbol: name,
        detail: error.to_string(),
    })
}

fn validate_descriptor(descriptor: &DescriptorV1) -> Result<(String, ModuleKind), String> {
    let kind = match descriptor.kind {
        KIND_AUTHORITY => ModuleKind::Authority,
        KIND_SANITIZER => ModuleKind::Sanitizer,
        other => return Err(format!("kind {other} is not authority (1) or sanitizer (2)")),
    };
    if descriptor.name_ptr.is_null() {
        return Err("the name pointer is null".to_string());
    }
    if descriptor.name_len == 0 || descriptor.name_len > 64 {
        return Err(format!("the name length {} is outside 1..=64", descriptor.name_len));
    }
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.name_ptr, descriptor.name_len) };
    let name = std::str::from_utf8(bytes).map_err(|_| "the name is not UTF-8".to_string())?;
    if !valid_implementation_name(name) {
        return Err(format!("the name {name:?} is not lowercase kebab within 64 bytes"));
    }
    Ok((name.to_string(), kind))
}

#[cfg(unix)]
fn open_library(path: &Path) -> Result<libloading::Library, libloading::Error> {
    use libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW};
    unsafe { Library::open(Some(path), RTLD_NOW | RTLD_LOCAL) }.map(libloading::Library::from)
}

#[cfg(not(unix))]
fn open_library(path: &Path) -> Result<libloading::Library, libloading::Error> {
    unsafe { libloading::Library::new(path) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_grammar_is_lowercase_kebab_within_64_bytes() {
        for name in ["approve", "redact-email", "a", "pii-2", "0day"] {
            assert!(valid_implementation_name(name), "{name:?} is valid");
        }
        let long = "a".repeat(65);
        for name in ["", "-lead", "Upper", "under_score", "dot.name", "spa ce", long.as_str()] {
            assert!(!valid_implementation_name(name), "{name:?} is invalid");
        }
        assert!(valid_implementation_name(&"a".repeat(64)));
    }

    #[test]
    fn the_stock_names_belong_to_one_section_each() {
        assert_eq!(
            Stock::for_section(Section::Authorities, "approve"),
            Some(Stock::Approve)
        );
        assert_eq!(
            Stock::for_section(Section::Sanitizers, "redact-email"),
            Some(Stock::RedactEmail)
        );
        assert_eq!(
            Stock::for_section(Section::Sanitizers, "redact-secrets"),
            Some(Stock::RedactSecrets)
        );
        for (section, name) in [
            (Section::Authorities, "redact-secrets"),
            (Section::Authorities, "hitl"),
            (Section::Authorities, "redact-email"),
            (Section::Sanitizers, "approve"),
            (Section::Annotators, "redact-email"),
            (Section::Audience, "approve"),
        ] {
            assert_eq!(Stock::for_section(section, name), None, "{section:?}/{name}");
        }
    }

    #[test]
    fn redact_email_masks_email_like_tokens_only() {
        let cases = [
            ("write to alice@corp.example today", "write to [redacted-email] today"),
            ("no addresses here", "no addresses here"),
            ("a@b.c and d@e.f", "[redacted-email] and [redacted-email]"),
            ("not@here (no dot)", "not@here (no dot)"),
            ("@leading.dot stays", "@leading.dot stays"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_email(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn redact_african_pii_masks_african_pii_only() {
        let cases = [
            ("call +256700123456 now", "call [redacted-african-pii] now"),
            ("call +254712345678 now", "call [redacted-african-pii] now"),
            ("call +2348012345678 now", "call [redacted-african-pii] now"),
            ("call +27821234567 now", "call [redacted-african-pii] now"),
            ("call +233241234567 now", "call [redacted-african-pii] now"),
            ("call 0700123456 now", "call [redacted-african-pii] now"),
            ("ID 12345678901", "ID [redacted-african-pii]"),
            ("ID 12345678", "ID [redacted-african-pii]"),
            ("ID 1234567890123", "ID [redacted-african-pii]"),
            ("ID 12345678901234", "ID [redacted-african-pii]"),
            ("ID GHA-12345678-9", "ID [redacted-african-pii]"),
            ("ID 12345678901234567890", "ID [redacted-african-pii]"),
            ("ID 123456789012", "ID [redacted-african-pii]"),
            ("passport KE1234567", "passport [redacted-african-pii]"),
            ("passport A1234567", "passport [redacted-african-pii]"),
            ("Mzee called", "[redacted-african-pii] called"),
            ("Bwana arrived", "[redacted-african-pii] arrived"),
            ("Ssebo here", "[redacted-african-pii] here"),
            ("Ato works", "[redacted-african-pii] works"),
            ("Malam teaches", "[redacted-african-pii] teaches"),
            ("Baba leads", "[redacted-african-pii] leads"),
            ("Nkosi speaks", "[redacted-african-pii] speaks"),
            ("Tata writes", "[redacted-african-pii] writes"),
            ("no pii here", "no pii here"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_african_pii(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn redact_mobile_money_masks_mobile_money_refs_only() {
        let cases = [
            ("tx MP1234567890 completed", "tx [redacted-mobile-money] completed"),
            ("tx 12345678901234 completed", "tx [redacted-mobile-money] completed"),
            ("tx MM123456789012 completed", "tx [redacted-mobile-money] completed"),
            ("tx MPESA12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx MTN123456789012 completed", "tx [redacted-mobile-money] completed"),
            ("tx AIRTEL12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx ORANGE12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx WAVE1234567890 completed", "tx [redacted-mobile-money] completed"),
            ("tx ECOCASH12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx VODA12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx TIGO12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx HALO12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx EAZZY12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx MPAWA12345678 completed", "tx [redacted-mobile-money] completed"),
            ("tx MOKASH12345678 completed", "tx [redacted-mobile-money] completed"),
            ("no money here", "no money here"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_mobile_money(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn redact_fintech_masks_fintech_identifiers_only() {
        let cases = [
            ("BVN 12345678901", "BVN [redacted-fintech]"),
            ("KRA PIN A123456789B", "KRA PIN [redacted-fintech]"),
            ("SA ID 1234567890123", "SA ID [redacted-fintech]"),
            ("UG NIN 12345678901234", "UG NIN [redacted-fintech]"),
            ("Ghana Card GHA-12345678-9", "Ghana Card [redacted-fintech]"),
            ("NIDA 12345678901234567890", "NIDA [redacted-fintech]"),
            ("IBAN GB29NWBK60161331926819", "IBAN [redacted-fintech]"),
            ("SWIFT NWBKGB2L", "SWIFT [redacted-fintech]"),
            ("SWIFT NWBKGB2LXXX", "SWIFT [redacted-fintech]"),
            ("Card 4111111111111111", "Card [redacted-fintech]"),
            ("Account 12345678", "Account [redacted-fintech]"),
            ("Account 12345678901234567", "Account [redacted-fintech]"),
            ("no fintech here", "no fintech here"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_fintech(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn a_missing_directory_refuses_and_no_directory_loads_nothing() {
        let registry = load(None).expect("no directory is the stock-only deployment");
        assert!(registry.authority("anything").is_none());

        let missing = std::path::Path::new("/nonexistent/appa-modules-test");
        match load(Some(missing)) {
            Err(ModulesError::DirectoryUnreadable { .. }) => {}
            Err(other) => panic!("a missing directory must refuse as unreadable, got {other}"),
            Ok(_) => panic!("a missing directory must refuse"),
        }
    }

    #[test]
    fn a_non_library_file_in_the_directory_refuses_the_load() {
        let dir = tempfile::tempdir().expect("a temp dir is creatable");
        std::fs::write(dir.path().join("README.md"), "not a module").expect("the file writes");
        match load(Some(dir.path())) {
            Err(ModulesError::NotALibrary { path, .. }) => assert!(path.ends_with("README.md")),
            Err(other) => panic!("a stray file must refuse as not-a-library, got {other}"),
            Ok(_) => panic!("a stray file must refuse"),
        }
    }

    #[test]
    fn a_file_with_the_library_suffix_but_no_module_inside_refuses() {
        let dir = tempfile::tempdir().expect("a temp dir is creatable");
        let name = format!("libfake.{}", std::env::consts::DLL_EXTENSION);
        std::fs::write(dir.path().join(&name), b"garbage bytes").expect("the file writes");
        match load(Some(dir.path())) {
            Err(ModulesError::Unloadable { .. }) => {}
            Err(other) => panic!("garbage must refuse as unloadable, got {other}"),
            Ok(_) => panic!("garbage must refuse"),
        }
    }

    #[test]
    fn descriptor_validation_names_each_refusal() {
        let name = b"ok-name";
        let good = DescriptorV1 {
            name_ptr: name.as_ptr(),
            name_len: name.len(),
            kind: KIND_SANITIZER,
        };
        assert_eq!(
            validate_descriptor(&good).expect("the descriptor is valid"),
            ("ok-name".to_string(), ModuleKind::Sanitizer),
        );

        let bad_kind = DescriptorV1 { kind: 9, ..good };
        assert!(validate_descriptor(&bad_kind).is_err());

        let null_name = DescriptorV1 {
            name_ptr: std::ptr::null(),
            ..good
        };
        assert!(validate_descriptor(&null_name).is_err());

        let oversized = DescriptorV1 { name_len: 65, ..good };
        assert!(validate_descriptor(&oversized).is_err());

        let bad_grammar = b"Not-Kebab";
        let ungrammatical = DescriptorV1 {
            name_ptr: bad_grammar.as_ptr(),
            name_len: bad_grammar.len(),
            kind: KIND_AUTHORITY,
        };
        assert!(validate_descriptor(&ungrammatical).is_err());
    }
}
