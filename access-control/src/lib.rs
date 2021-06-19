use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use argon2::password_hash::SaltString;
use argon2::Params;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

/// Memory cost of 15 MiB as per
/// (OWASP)[https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id]
pub const ARGON2_M_COST: u32 = 15 * 1024;

/// 2 Iterations as per
/// (OWASP)[https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id]
pub const ARGON2_T_COST: u32 = 2;

/// Degree of parallelism of 1 as per
/// (OWASP)[https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id]
pub const ARGON2_P_COST: u32 = 1;

/// Fake hash used to archive constant time in the authentication function.
///
/// The PHC hash is derived from an empty password.
pub const FAKE_PHC_HASH: &'static str =
    "$argon2id$v=19$m=15360,t=2,p=1$saltsaltsaltsalt$1hx6lvjIBIrxykf2XmEdsNUxMAsJ6FBKtP5g4R0UygY";

/// Access-Control errors for authentication and authorization
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The error to return when authentication failed
    ///
    /// Authentication is the process of verifying a persons identity.
    /// A error when verifying a users permission is an authorization error.
    #[error("Invalid credentials")]
    Authentication,
    /// The error to return when authorization failed
    ///
    /// Authorization is the process of verifying a persons permissions to manipulate, create or read data.
    /// A error when verifying a users identity is an authentication error.
    #[error("Permission denied")]
    Authorization,
    /// The error to return when the registration failed because the username is invalid
    #[error("Username does not match the policy")]
    UsernamePolicy,
    /// The error to return when the password is insufficient
    #[error("Password does not match the policy")]
    PasswordPolicy,
}

/// The Backend trait defines the operations of the database layer.
///
/// To implement a backend you will need to provide a valid [`User`].
/// # Backend operations
/// Currently there is ony the [`Backend::get_user`] method that needs to be implemented to build a valid backend.
/// This function retrieves a user from the database by providing a username and password.
/// # Implementations
/// Currently there is the PostgreSqlBackend which implements an example workflow for the backend.
pub trait Backend<U>: Clone
where
    U: User,
{
    fn get_user(&self, username: impl AsRef<str>) -> Pin<Box<dyn Future<Output = Option<U>>>>;
    fn get_user_from_session(
        &self,
        session_id: impl AsRef<str>,
    ) -> Pin<Box<dyn Future<Output = Option<U>>>>;
    fn register_user(
        &self,
        username: impl AsRef<str>,
        password_hash: impl AsRef<str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>>>>;
    fn store_session(
        &self,
        user: &U,
        session_id: impl AsRef<str>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>>>>;
    fn remove_session(&self, session_id: impl AsRef<str>) -> Pin<Box<dyn Future<Output = ()>>>;
}

/// The User trait defines the operations of a User that are necessary to be handled by the middleware.
/// # User operations
/// The user trait forces two methods that need to be implemented.
/// 1. The [`User::name`] method that returns a users name as `&str`.
/// 2. The [`User::capabilities`] method that returns a users capabilities inside a `&HashSet<String>`
///
/// Capabilities are just a collection of Strings that describe the operations a user is allowed to do.
/// For example, a normal Administrator could have the capabilities of `hash_set!{ "Admin", "AdminRead", "AdminWrite"};`.
pub trait User {
    fn username(&self) -> &str;
    fn password_hash(&self) -> &str;
    fn capabilities(&self) -> &HashSet<String>;
}

fn get_argon2_ctx() -> Argon2<'static> {
    let params = Params::default();
    Argon2::new(
        None,
        ARGON2_T_COST,
        ARGON2_M_COST,
        ARGON2_P_COST,
        params.version,
    )
    .expect("invalid argon2 parameters")
}

/// AccessControl defines the behavior of a `Backend<impl User>` and ensures its safety at compile time.
/// This safety is guaranteed by the implementation of the [typestate pattern](http://cliffle.com/blog/rust-typestate/).
///
/// In the case of the AccessControl struct we use the states [`Start`], [`Authenticated`] and [`Authorized`] to ensure that operations are executed in the correct order.
/// # Operations
/// The AccessControl defines multiple operations stretched over multiple states.
/// 1. **Start** provides the [`AccessControl::new`] and [`AccessControl::authenticate`] method
/// 2. **Authenticated** provides the [`AccessControl::authorize`] method
/// 3. **Authorized** provides the [`AccessControl::get_user`] method
///
/// # Definition
/// To use the AccessControl an implementation of a Backend and therefore User is necessary.
#[derive(Debug, Clone)]
pub struct AccessControl<S, B, U>
where
    S: AccessControlState,
    B: Backend<U>,
    U: User,
{
    state: S,
    backend: B,
    user: Option<U>,
}

impl<B, U> AccessControl<Start, B, U>
where
    B: Backend<U>,
    U: User,
{
    /// Create a new AccessControl in the state `Start` by providing a `Backend<impl User>`
    pub fn new(backend: B) -> Self {
        Self {
            state: Start,
            backend,
            user: None,
        }
    }
}

impl<B, U> AccessControl<Start, B, U>
where
    B: Backend<U>,
    U: User,
{
    /// Authenticate a user by providing a username and password. This function must be constant time.
    ///
    /// The authentication process is implemented by the provided `Backend<impl User>` and its `get_user` method.
    ///
    /// This method may return [`Error::Authentication`] on error, otherwise it returns a AccessControl in the state [`Authenticated`].
    pub async fn authenticate_creds(
        self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<AccessControl<Authenticated, B, U>, Error> {
        let user = self.backend.get_user(username).await;

        // We can't do an early return if the user does not exist in the database so
        // we verify with a fake hash
        // Maybe constant time with https://docs.rs/subtle/2.4.0/subtle/struct.CtOption.html?
        let fake_parsed_hash =
            PasswordHash::new(FAKE_PHC_HASH).expect("fake hash is invalid PHC hash");
        let parsed_hash = match user {
            Some(ref user) => PasswordHash::new(user.password_hash()).unwrap_or(fake_parsed_hash),
            None => fake_parsed_hash,
        };

        match get_argon2_ctx().verify_password(password.as_ref().as_bytes(), &parsed_hash) {
            Ok(_) => Ok(AccessControl {
                state: Authenticated,
                backend: self.backend,
                // If the password verifies, the user is some!
                user,
            }),
            Err(_) => Err(Error::Authentication),
        }
    }

    pub async fn authenticate_session(
        self,
        session_id: impl AsRef<str>,
    ) -> Result<AccessControl<Authenticated, B, U>, Error> {
        let user = self
            .backend
            .get_user_from_session(session_id)
            .await
            .ok_or(Error::Authentication)?;
        Ok(AccessControl {
            state: Authenticated,
            backend: self.backend,
            user: Some(user),
        })
    }

    /// Register a new user account
    ///
    /// The actual registration with the backend should be constant time. Otherwise an attacker could try to register
    /// already existing usernames and see if the registration takes longer than if the username does not exist.
    /// Furthermore, no error is returned, if the user does already exists, only if the username or password does not
    /// match the policy.
    pub async fn register(
        self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<(), Error> {
        let username = username.as_ref().to_lowercase();

        if username.is_empty() || !username.chars().all(|c| char::is_ascii_alphanumeric(&c)) {
            return Err(Error::UsernamePolicy);
        }

        if password.as_ref().chars().count() < 12 || password.as_ref().chars().count() > 256 {
            return Err(Error::PasswordPolicy);
        }

        let salt = SaltString::generate(rand::thread_rng());
        let password_hash = get_argon2_ctx()
            .hash_password_simple(password.as_ref().as_bytes(), salt.as_ref())
            .unwrap()
            .to_string();

        self.backend
            .register_user(username, password_hash)
            .await
            // Ignore the error case
            .unwrap_or(());

        // Return ok even if the registration with the backend failed
        Ok(())
    }
}

impl<B, U> AccessControl<Authenticated, B, U>
where
    B: Backend<U>,
    U: User,
{
    /// Authorize a user by passing in a `&HashSet<String>` of capabilities and comparing it to the users capabilities.
    ///
    /// If the users capabilities are a superset of the required_capabilities, the method returns a [`AccessControl`] in the [`Authorized`] state.
    /// Otherwise it will return an error of the type [`Error::Authorization`].
    pub fn authorize(
        self,
        required_capabilities: &HashSet<String>,
    ) -> Result<AccessControl<Authorized, B, U>, Error> {
        if !self
            .user
            .as_ref()
            .expect("user is always available in authenticated state")
            .capabilities()
            .is_superset(required_capabilities)
        {
            return Err(Error::Authorization);
        }

        Ok(AccessControl {
            state: Authorized,
            backend: self.backend,
            user: self.user,
        })
    }
}

impl<B, U> AccessControl<Authorized, B, U>
where
    B: Backend<U>,
    U: User,
{
    /// After the user is authenticated and authorized, this method can be used to retrieve the user.
    ///
    /// The call to this function will always succeed as the [typestate pattern](http://cliffle.com/blog/rust-typestate/) makes sure the user is valid, authenticated and authorized.
    pub fn get_user(self) -> U {
        self.user
            .expect("user is always available in authorized state")
    }
}

// TODO: Seal https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
/// The [AccessControlState] trait can be implemented to add another state to the [`AccessControl`] struct.
/// It is part of the compile time safety check implemented using the [typestate pattern](http://cliffle.com/blog/rust-typestate/).
pub trait AccessControlState {}
/// The initial state of the [`AccessControl`] struct when initializing it with [`AccessControl::new`].
/// For details see: [`AccessControl`]
pub struct Start;
/// The [`AccessControl`] struct after a user has been successfully authenticated by reading them from the database with [`AccessControl::authenticate`].
/// For details see: [`AccessControl`]
pub struct Authenticated;
/// The state of [`AccessControl`] after a user has been successfully authenticated and authorized by comparing them to the required capabilities with [`AccessControl::authorize`].
/// For details see: [`AccessControl`]
pub struct Authorized;

impl AccessControlState for Start {}
impl AccessControlState for Authenticated {}
impl AccessControlState for Authorized {}
