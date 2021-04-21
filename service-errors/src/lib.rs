use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde::Serialize;

/// Enum of the available errors in the auth-service.
#[derive(thiserror::Error, Debug)]
pub enum AuthServiceError {
    #[error("User {email:?} not found")]
    UserNotFound { email: String },
    #[error("User {email:?} could not be registered")]
    UserRegistrationFailed { email: String },
    #[error("Internal Error")]
    Default,
}

impl AuthServiceError {
    /// Returns the name of a certain error
    fn name(&self) -> String {
        match self {
            Self::UserRegistrationFailed { .. } => "UserRegistrationFailed".into(),
            Self::UserNotFound { .. } => "UserNotFound".into(),
            Self::Default => "Internal Error".into(),
        }
    }
}

/// Implements a custom response for actix web when returning an
/// AuthServiceError
///
/// source: https://mattgathu.dev/2020/04/16/actix-web-error-handling.html
impl ResponseError for AuthServiceError {
    fn status_code(&self) -> StatusCode {
        match *self {
            Self::UserRegistrationFailed { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound { .. } => StatusCode::NOT_FOUND,
            Self::Default => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_response = ErrorResponse {
            code: status_code.as_u16(),
            error: self.name(),
            message: self.to_string(),
        };
        HttpResponse::build(status_code).json(error_response)
    }
}

/// Automatically called by Actix when returning an AuthServiceError
///
/// Builds a json response from the error which contains the error-code,
/// error-type and error-message
#[derive(Serialize)]
struct ErrorResponse {
    code: u16,
    error: String,
    message: String,
}
