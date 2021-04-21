use std::pin::Pin;
use std::task::{Context, Poll};

use access_control::{AccessControl, PostgreSqlBackend, User};
use actix_service::{Service, Transform};
use actix_web::{
    dev::ServiceRequest,
    dev::ServiceResponse,
    error::{ErrorBadRequest, ErrorForbidden},
    Error,
};
use futures::future::{ok, Ready};
use futures::Future;

pub struct SimpleStringMiddleware {
    pub permission: String,
}

impl<S, B> Transform<S> for SimpleStringMiddleware
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthorizationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthorizationMiddleware {
            backend: PostgreSqlBackend,
            permission: self.permission.clone(),
            service,
        })
    }
}

pub struct AuthorizationMiddleware<S> {
    backend: PostgreSqlBackend,
    permission: String,
    service: S,
}

impl<S, B> Service for AuthorizationMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let authorization = match req
            .headers()
            .get("Authorization")
            .ok_or(ErrorBadRequest("Missing Authorization header"))
        {
            // I already wrote a JWT token middleware, this is just an example
            Ok(header) => header.to_str().unwrap_or("default"),
            Err(err) => return Box::pin(async move { Err(err) }),
        };

        let check_access = || -> Result<User, Error> {
            Ok(AccessControl::new(self.backend.clone())
                .authenticate(authorization)
                .map_err(|_| ErrorBadRequest("Invalid credentials"))?
                .authorize(&self.permission)
                .map_err(|_| ErrorForbidden("Permission Denied"))?
                .get_user())
        };

        match check_access() {
            Ok(user) => {
                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                })
            }
            Err(e) => Box::pin(async move { Err(e) }),
        }
    }
}
