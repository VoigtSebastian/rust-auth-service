fn main() {
    dotenv::dotenv().ok();
    println!("{:?}", std::env::var("DATABASE_URL"));
    println!("{}", service_errors::AuthServiceError::Default);
}
