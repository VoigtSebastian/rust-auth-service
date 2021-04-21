use service_errors::ServiceError;

pub fn user_lookup_error(error: sqlx::Error, email: &String) -> ServiceError {
    match error {
        sqlx::Error::RowNotFound => ServiceError::UserNotFound {
            email: email.clone(),
        },
        _ => ServiceError::Default,
    }
}

pub fn user_registration_error(error: sqlx::Error, email: &String) -> ServiceError {
    match error {
        _ => ServiceError::UserRegistrationFailed {
            email: email.clone(),
        },
    }
}
