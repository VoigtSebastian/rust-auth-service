use actix_web::Result;
use authorization::UserDetails;

/// Used to access public information
pub async fn retrieve_public_information() -> Result<String> {
    Ok("public information".to_string())
}

/// Used to access mocked user-specific information
pub async fn retrieve_user_information() -> Result<String> {
    Ok("user information".to_string())
}

/// Used to access mocked admin-specific information
pub async fn retrieve_admin_information(user: UserDetails) -> Result<String> {
    Ok(format!("{:?}", user.0))
}
