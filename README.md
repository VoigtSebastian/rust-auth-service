# rust-auth-service

The rust-auth-service is an authentication and authorization service written in Rust as part of the Programming in Rust lecture at the HTWG Konstanz.
In addition to a library that provides the auth functionality, it implements an example actix-web server and web-frontend.

## Goals

1. Get a basic understanding of Rust, its features and write some Rust-idiomatic code
2. Get an idea of what it takes to write a reasonably secure auth service
3. Document and test our code

## How to

To use the example implementation of this service, you should have a working docker (or podman) installation on your system, otherwise the automation-script will need some minor changes.

To run the database execute the command `./automation.sh container start` after the container is running, execute `./automation.sh db up` to create the database-schema for this database.

Before running the service you have to create a certificate by running `./automation.sh gencert`.
This command will run `openssl` and create the files `cert.pem`and `key.pem`.

After starting the database and creating its schema, you can execute `cargo build --workspace` and `cargo run` to run the service with its default values.
The default values are part of the `.env` file which includes the database URI, which is generated by running `./automation.sh psql-uri` and the logging level.

To access the web-interface, visit `https://localhost:8080/`.

Your browser will probably (_hopefully_) tell you, that this is an unsafe connection, because the certificate was self-signed.
In every other circumstance, you should consider what decision let you to this point in your life and return to safety.
This time, you can tell your browser that you know what you are doing (if you do so) and enter the website.
In general, the [security section](#security) should be considered when working with this project.

### For the lazy ones

1. `./automation.sh container start`
2. `./automation.sh db up`
3. `./automation gencert`
4. `cargo build --workspace`
5. `cargo run`
6. Visit [https://localhost:8080/](https://localhost:8080/)

## Security

### Considerations

This is written by two students, the service **hasn't been audited** and is meant as a study-exercise with room to expand.
There are most likely multiple security issues that we just don't know about or haven't found yet.

If are interested in giving feedback or found an issue with the implementation, please open an issue and let us know ❤️

Additionally:

1. **The default values in `.env` and `automation.sh`** are not meant for production
2. The service is **not meant for production**
3. SQLx — our SQL library — does not support 1:n mapping. This might be a security issue in our User implementation, as we need two queries to access a user and their capabilities.

With the disclaimer out of the way, we tried to at least pay attention to
security. What has been considered security wise:

- Secure password storage with Argon2 as recommended per OWASP
- Prevention of username enumeration by timing attacks (incomplete)
- Generic error messages
- Cookie handling and session protection
- Enforced Authentication at compile time with typestates
- Authorization based on capabilities
- Strict Content Security Policy for XSS and Session Hijacking prevention
- And obviously HTTPS

However not everything is perfect. Currently, we don't issue CSRF tokens.
2FA/MFA is missing and realistically a heap of stuff we didn't even think about.

## Project structure

This projects uses cargo workspace to organize the project into multiple crates, currently there are 4 crates.
In addition to the 4 rust crates, the `sql` subdirectory contains the `up.sql`and `down.sql` scripts used to initialize the database.

### Workspace

- **src/** the executable crate that builds the example web server
- **database-integration** contains all the database specific code, that is used in the example application5
- **middlware** contains the actix-web handle session authorization/authentication
- **access-control** control contains the code, that is used to control a users access by the backend

The auth library consists of two crates, `access-control`and `middleware`.
The `access-control` crate contains two traits `User` and `Backend` and additionally the struct `AccessControl`.
The `middleware` crate contains the actix-web middleware that uses those traits to check a request's validity.

The `main` crate in the projects root and the crate `database-integration` implement the traits provided by `access-control` and use them to build an executable application.
The `database-integration` crate contains the `User` and `PostgreSqlBackend` implementation which provide access to the PostgreSQL database to the `RustAuthMiddleware` and `AccessControl`.

## Data Flow

The basic flow of data starts with an HTTP request.
If the requests is to an existing route, that is using the `RustAuthMiddleware`, the request will be handled in one of two following ways.

### The user is not logged in / registered

TODO: description of login process

Respond with a redirect to the login page.
This gets indirectly triggered by the `RustAuthMiddleware`, as it returns an error with the status-code UNAUTHORIZED, which will then be caught by an ErrorHandler.
This way, a user that is trying to get access to the website, but is not logged in, will always end up at the login page.

```rust
// middleware/src/lib.rs ; line 193
// Tries to retrieve a user from the database an returns an ErrorUnauthorized if this fails.
// The same behavior is used in multiple parts of the middleware.
let user = AccessControl::new(item.backend.clone())
            .authenticate_creds(username, password)
            .await
            .map_err(ErrorUnauthorized)?

// src/main.rs ; line 64
// Register an error handler that redirects to the login page
App::new()
    .wrap(
        ErrorHandlers::new()
            .handler(http::StatusCode::UNAUTHORIZED, routes::login_redirect),
    )

// src/routes.rs ; line 22
// The actual redirect response
pub fn login_redirect(res: dev::ServiceResponse) -> Result<ErrorHandlerResponse<dev::Body>> {
    Ok(ErrorHandlerResponse::Response(ServiceResponse::new(
        res.request().clone(),
        HttpResponse::Found()
            .header(header::LOCATION, "/login")
            .finish(),
    )))
}
```

### The user is logged in

Authorize the user by checking their capabilities and check if they are a superset of the required capabilities.
TODO: description of user extraction

## Build the documentation

To build and open the documentation of this workspace, without building the documentation of every crate it depends on, run `./automation doc`.
This is meant as a developer documentation, as it includes private items by using the `--document-private-items` flag.

The command that is executed by running `./automation doc` is `cargo doc --workspace --no-deps --document-private-items --open`.

## Automation

There are multiple directions of automation in this projects.

There is local automation by manually running the `automation.sh` script, that automates repetitive tasks.

Git automation using [rusty-hook](https://lib.rs/crates/rusty-hook) that checks for errors before committing and pushing to the repository.

And finally, there is remote automation using GitHub Actions.
Every time a pull-requests gets opened for this repository an automatic GitHub-Action is run that executes all tests in the cargo-workspace, including the tests that use the PostgreSQL database.

## Customization

There are many ways this project can be customized, from the actual implementation of the User and Backend trait to simple environment variables.

### Environment variables

The .env file in the projects base-directory contains multiple variables that can be manipulated to make the service behave differently.

- **DATABASE_URL**: The [PostgreSQL URI](https://www.postgresql.org/docs/9.3/libpq-connect.html#AEN39692) that the service uses
- **RUST_LOG**: The current log level for the [env_logger](https://docs.rs/log/0.4.14/log/enum.Level.html)
- **SERVICE_DOMAIN**:: The domain the service uses (e.g. localhost)
- **SERVICE_PORT**: The port the service uses (e.g. 80)

## Development

This software has been written be [Benjamin Faller](https://github.com/b-faller) and [Sebastian Voigt](https://github.com/VoigtSebastian).

## LICENSE

This project is, as most Rust projects are, licensed under the MIT License.
