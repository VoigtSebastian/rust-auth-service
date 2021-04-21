use service_errors::AuthServiceError;

pub fn user_lookup_error(error: sqlx::Error, email: &String) -> AuthServiceError {
    match error {
        sqlx::Error::RowNotFound => AuthServiceError::UserNotFound {
            email: email.clone(),
        },
        _ => AuthServiceError::Default,
    }
}

pub fn user_registration_error(error: sqlx::Error, email: &String) -> AuthServiceError {
    match error {
        _ => AuthServiceError::UserRegistrationFailed {
            email: email.clone(),
        },
    }
}
