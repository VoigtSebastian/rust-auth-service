use service_errors::ServiceError;

pub fn user_lookup_error(error: sqlx::Error, email: &str) -> ServiceError {
    match error {
        sqlx::Error::RowNotFound => ServiceError::UserNotFound {
            email: email.into(),
        },
        _ => ServiceError::Default,
    }
}

pub fn user_registration_error(error: sqlx::Error, email: &str) -> ServiceError {
    match error {
        _ => ServiceError::UserRegistrationFailed {
            email: email.into(),
        },
    }
}
