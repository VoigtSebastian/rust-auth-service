use actix_web::Result;
use authorization::UserDetails;
use database_integration::user::User;

/// Used to access public information
pub async fn retrieve_public_information() -> Result<String> {
    Ok("public information".to_string())
}

/// Used to access mocked user-specific information
pub async fn retrieve_user_information(user: UserDetails<User>) -> Result<String> {
    Ok(format!("User information: {:?}", user.0))
}

/// Used to access mocked admin-specific information
pub async fn retrieve_admin_information(user: UserDetails<User>) -> Result<String> {
    Ok(format!("Admin information: {:?}", user.0))
}
