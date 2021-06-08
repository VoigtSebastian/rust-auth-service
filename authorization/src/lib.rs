use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use access_control::AccessControl;
use access_control::Backend;
use access_control::User;

use actix_service::{Service, Transform};
use actix_web::dev::{Payload, PayloadStream};
use actix_web::error::ErrorInternalServerError;
use actix_web::{
    dev::ServiceRequest,
    dev::ServiceResponse,
    error::{ErrorBadRequest, ErrorForbidden},
    Error,
};
use actix_web::{FromRequest, HttpMessage, HttpRequest};
use futures_core::Future;
use futures_util::future::{ok, Ready};

pub struct SimpleStringMiddleware<T: Backend<User>> {
    pub backend: T,
    pub permission: String,
}

impl<S, B, T> Transform<S> for SimpleStringMiddleware<T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    T: Backend<User> + 'static,
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
            permission: self.permission.clone(),
            service: Rc::new(RefCell::new(service)),
        })
    }
}

/// Actix Web middleware to facilitate access control for Actix services.
pub struct AuthorizationMiddleware<S, T>
where
    T: Backend<User>,
{
    backend: T,
    permission: String,
    /// TODO: Check whether the `Rc<RefCell<S>>` structure is properly implemented and safe.
    /// Especially race conditions have not been checked yet.
    service: Rc<RefCell<S>>,
}

impl<S, B, T> Service for AuthorizationMiddleware<S, T>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    T: Backend<User> + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut srv = self.service.clone();
        let required_perms = self.permission.clone();
        let backend = self.backend.clone();

        Box::pin(async move {
            // FIXME: Use cookie sessions
            let (email, password) = match req
                .headers()
                .get("Authorization")
                .ok_or(ErrorBadRequest("Missing Authorization header"))
            {
                // I already wrote a JWT token middleware, this is just an example
                Ok(header) => {
                    let mut iter = header
                        .to_str()
                        .unwrap_or("default")
                        .splitn(2, '#')
                        .map(|s| s.to_string());
                    let email = iter.next().unwrap();
                    let password = iter.next().unwrap();
                    (email, password)
                }
                Err(err) => return Err(err),
            };

            // FIXME: Refactor into function
            let check_access = || -> Pin<Box<dyn Future<Output = Result<(), Error>>>> {
                Box::pin(async {
                    let user = AccessControl::new(backend)
                        .authenticate(&email, &password)
                        .await
                        .map_err(|_| ErrorBadRequest("Invalid credentials"))?
                        .authorize(&required_perms)
                        .map_err(|_| ErrorForbidden("Permission Denied"))?
                        .get_user();
                    req.extensions_mut().insert(user);
                    Ok(())
                })
            };

            match check_access().await {
                Ok(_) => {
                    let res = srv.call(req).await?;
                    Ok(res)
                }
                Err(e) => Err(e),
            }
        })
    }
}

pub struct UserDetails(pub User);

impl FromRequest for UserDetails {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Error>>>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload<PayloadStream>) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            req.extensions()
                .get::<User>()
                .map(|u| UserDetails(u.clone()))
                .ok_or_else(|| ErrorInternalServerError("User not found"))
        })
    }
}
