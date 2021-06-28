//! Contains the middleware implementation that uses generics to provide the desired behavior.

use std::cell::RefCell;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use access_control::{AccessControl, Backend};

use actix_service::{Service, Transform};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::{Payload, PayloadStream, ServiceRequest, ServiceResponse};
use actix_web::error::{
    ErrorBadRequest, ErrorForbidden, ErrorInternalServerError, ErrorUnauthorized,
};
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest};
use futures_core::Future;
use futures_util::future::{ok, Ready};
use rand::RngCore;
use time::{Duration, OffsetDateTime};

/// A simple type to describe a dynamic Future to make clippy happy.
type DynamicFutureReturn<R> = Pin<Box<dyn Future<Output = R>>>;

pub struct RustAuthMiddleware<T>
where
    T: Backend,
{
    pub backend: T,
    pub required_capabilities: HashSet<String>,
}

impl<T> RustAuthMiddleware<T>
where
    T: Backend,
{
    pub fn new(backend: T, required_capabilities: HashSet<String>) -> Self {
        Self {
            backend,
            required_capabilities,
        }
    }
}

impl<S, B, T> Transform<S> for RustAuthMiddleware<T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    T: Backend + Clone + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthorizationMiddleware<S, T>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthorizationMiddleware {
            backend: self.backend.clone(),
            required_capabilities: self.required_capabilities.clone(),
            service: Rc::new(RefCell::new(service)),
        })
    }
}

/// Actix Web middleware to facilitate access control for Actix services.
pub struct AuthorizationMiddleware<S, T>
where
    T: Backend,
{
    backend: T,
    required_capabilities: HashSet<String>,
    /// TODO: Check whether the `Rc<RefCell<S>>` structure is properly implemented and safe.
    /// Especially race conditions have not been checked yet.
    service: Rc<RefCell<S>>,
}

impl<S, B, T> Service for AuthorizationMiddleware<S, T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    T: Backend + Clone + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = DynamicFutureReturn<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut srv = self.service.clone();
        let required_caps = self.required_capabilities.clone();
        let backend = self.backend.clone();

        Box::pin(async move {
            let item = SessionStateItem {
                actions: Vec::new(),
                backend: backend.clone(),
                required_caps,
            };
            req.extensions_mut().insert(item);

            let fut = srv.call(req);
            let mut res = fut.await?;

            let item = res
                .request()
                .extensions_mut()
                .remove::<SessionStateItem<T>>()
                .unwrap();

            for action in item.actions {
                match action {
                    SessionStateAction::Login(session_id) => {
                        // Add cookie
                        let cookie = Cookie::build("id", session_id)
                            .secure(true)
                            .http_only(true)
                            .same_site(SameSite::Lax)
                            .path("/")
                            .finish();
                        res.response_mut().add_cookie(&cookie).unwrap();
                    }
                    SessionStateAction::Logout => {
                        if let Some(mut cookie) = res.request().cookie("id") {
                            // Remove database session
                            let _ = backend.remove_session(cookie.value()).await;
                            // Delete the cookie
                            cookie.set_value("");
                            cookie.set_max_age(Duration::zero());
                            cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(365));
                            res.response_mut().add_cookie(&cookie).unwrap();
                        }
                    }
                }
            }

            Ok(res)
        })
    }
}

#[derive(Debug, Clone)]
enum SessionStateAction {
    Login(String),
    Logout,
}

#[derive(Debug)]
struct SessionStateItem<B>
where
    B: Backend,
{
    actions: Vec<SessionStateAction>,
    backend: B,
    required_caps: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct SessionState<B>
where
    B: Backend,
{
    req: HttpRequest,
    phantom: PhantomData<B>,
}

impl<B> SessionState<B>
where
    B: Backend + Clone + 'static,
{
    pub async fn login(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<B::User, Error> {
        let mut extensions = self.req.extensions_mut();
        let item = extensions
            .get_mut::<SessionStateItem<B>>()
            .ok_or_else(|| ErrorInternalServerError("extractor failed"))?;

        // https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#user-ids
        let username = username.as_ref().to_lowercase();

        let user = AccessControl::new(item.backend.clone())
            .authenticate_creds(username, password)
            .await
            .map_err(ErrorUnauthorized)?
            .authorize(&HashSet::new())
            .expect("no capabilities required to login")
            .get_user();

        // Use 256 bit length for the session ID. This is double of the minimum required by OWASP.
        let mut key = [0u8; 32];
        // ThreadRng uses a CSPRNG as per
        // https://rust-random.github.io/rand/rand/rngs/index.html#our-generators
        rand::thread_rng().fill_bytes(&mut key);
        let session_id = base64::encode(key);

        item.backend
            .store_session(&user, &session_id)
            .await
            .map_err(|_| ErrorInternalServerError("backend unavailable"))?;

        item.actions.push(SessionStateAction::Login(session_id));

        Ok(user)
    }

    pub async fn logout(&self) {
        if let Some(item) = self.req.extensions_mut().get_mut::<SessionStateItem<B>>() {
            item.actions.push(SessionStateAction::Logout);
        }
    }

    /// TODO: Think about what is required to register a user. Maybe other appliances want to store additional user
    /// details like first or last name ...
    pub async fn register(
        &self,
        username: impl AsRef<str>,
        password_hash: impl AsRef<str>,
    ) -> Result<(), Error> {
        let mut extensions = self.req.extensions_mut();
        let item = extensions
            .get_mut::<SessionStateItem<B>>()
            .ok_or_else(|| ErrorInternalServerError("extractor failed"))?;

        AccessControl::new(item.backend.clone())
            .register(username, password_hash)
            .await
            .map_err(ErrorBadRequest)
    }
}

impl<B> FromRequest for SessionState<B>
where
    B: Backend,
{
    type Config = ();
    type Error = Error;
    type Future = Ready<Result<SessionState<B>, Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ok(SessionState {
            req: req.clone(),
            phantom: PhantomData,
        })
    }
}

pub struct UserDetails<B>
where
    B: Backend,
{
    pub user: B::User,
}

impl<B> FromRequest for UserDetails<B>
where
    B: Backend + Clone + 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Error>>>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload<PayloadStream>) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            let err = || ErrorUnauthorized(access_control::Error::Authentication);

            let cookie = req.cookie("id").ok_or_else(err)?;
            let mut extensions = req.extensions_mut();
            let item = extensions
                .get_mut::<SessionStateItem<B>>()
                .ok_or_else(err)?;

            // Authenticate and authorize with the session ID
            let user = AccessControl::new(item.backend.clone())
                .authenticate_session(cookie.value())
                .await
                .map_err(ErrorUnauthorized)?
                .authorize(&item.required_caps)
                .map_err(ErrorForbidden)?
                .get_user();

            Ok(UserDetails { user })
        })
    }
}
