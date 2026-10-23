//! Typed API errors and the response codes they come from (`ResponseCodes.cs` in win-app).

use std::time::Duration;

use serde_json::Value;

pub const CODE_OK: i64 = 1000;
pub const CODE_OK_MULTI: i64 = 1001;
pub const CODE_INCORRECT_CREDENTIALS: i64 = 8002;
pub const CODE_SWITCH_TO_SSO: i64 = 8100;
pub const CODE_HUMAN_VERIFICATION_REQUIRED: i64 = 9001;
pub const CODE_OUTDATED_APP: i64 = 5003;
pub const CODE_OUTDATED_API: i64 = 5005;
pub const CODE_INVALID_HUMAN_VERIFICATION_TOKEN: i64 = 12087;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("cannot reach the Proton API: {0}")]
    Network(#[source] reqwest::Error),

    /// A well-formed error reply (`{Code, Error, Details}`).
    #[error("{message} (code {code}, HTTP {status})")]
    Api { status: u16, code: i64, message: String, details: Option<Value> },

    #[error("Proton asks for human verification (CAPTCHA), which can't be completed in a terminal. {}", .0.hint())]
    HumanVerificationRequired(HumanVerification),

    #[error("the Proton API rejected this client version: {0}")]
    AppVersionRejected(String),

    /// The session is missing, expired, or could not be refreshed. Sign in again.
    #[error("not signed in, or the session has expired")]
    Unauthorized,

    /// HTTP 429 (rate limited) or 503 (unavailable), after the client's own short retries.
    #[error("the Proton API asked to retry later (HTTP {status}){}", retry_hint(.retry_after))]
    RetryLater { status: u16, retry_after: Option<Duration> },

    #[error("unexpected API response: {0}")]
    InvalidResponse(String),

    /// Finding or using an alternative route failed (T6.3).
    #[error("alternative routing: {0}")]
    AlternativeRouting(String),
}

impl ApiError {
    /// The API's `Code`, when the error came from an API reply.
    pub fn code(&self) -> Option<i64> {
        match self {
            ApiError::Api { code, .. } => Some(*code),
            ApiError::HumanVerificationRequired(_) => Some(CODE_HUMAN_VERIFICATION_REQUIRED),
            _ => None,
        }
    }
}

/// What the API returned with code 9001.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanVerification {
    pub token: String,
    /// e.g. `captcha`, `email`, `sms`.
    pub methods: Vec<String>,
    /// Page that shows the challenge (what win-app embeds).
    pub web_url: String,
}

impl HumanVerification {
    fn hint(&self) -> String {
        format!(
            "Wait a while and retry, or sign in once at https://account.proton.me from this network. Challenge: {}",
            self.web_url
        )
    }
}

fn retry_hint(retry_after: &Option<Duration>) -> String {
    match retry_after {
        Some(d) => format!("; retry in {} s", d.as_secs().max(1)),
        None => String::new(),
    }
}
