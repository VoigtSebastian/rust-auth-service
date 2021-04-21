fn main() {
    dotenv::dotenv().ok();
    println!("{:?}", std::env::var("DATABASE_URL"));
}
