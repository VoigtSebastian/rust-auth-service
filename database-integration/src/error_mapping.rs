use service_errors::ServiceError;

pub fn user_lookup_error(error: sqlx::Error, username: &str) -> ServiceError {
    match error {
        sqlx::Error::RowNotFound => ServiceError::UserNotFound {
            username: username.into(),
        },
        _ => ServiceError::Default,
    }
}

pub fn user_registration_error(error: sqlx::Error, username: &str) -> ServiceError {
    match error {
        _ => ServiceError::UserRegistrationFailed {
            username: username.into(),
        },
    }
}
