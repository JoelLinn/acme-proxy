#[macro_use] extern crate log;

use actix_http::http::{header};
use actix_web::{web, Error, error, client::Client, Result, http::StatusCode, App, HttpRequest, HttpResponse, HttpServer};
use regex::Regex;

struct ProxyConf {
    re_valid_host: Regex,
    re_legal_host: Regex,
    timeout: Option<core::time::Duration>,
}

async fn proxy(
    req: HttpRequest,
    client: web::Data<Client>,
    c: web::Data<ProxyConf>,
) -> Result<HttpResponse, Error> {
    let token = match req.match_info().get("token") {
        Some(t) => t,
        None => return Err(error::ErrorNotExtended("Token undefined.")),
    };

    let host = match req.headers()
        .get(header::HOST)
        .and_then(|host_value| host_value.to_str().ok()) {
            Some(s) => s,
            None => return Err(error::ErrorBadRequest("Empty host.")),
        };

    if host == "localhost" || !c.re_valid_host.is_match(host) {
        return Err(error::ErrorBadRequest(format!("Invalid host name: '{}'", host)))
    }

    // user filter for legal subdomains or list of hosts
    if !c.re_legal_host.is_match(host) {
        return Err(error::ErrorForbidden(format!("Illegal host name: '{}'", host)))
    }

    let uri = format!("http://{}/.well-known/acme-challenge/{}", host, token);
    info!("Forwarding challenge to '{}'.", uri);

    let mut proxied_response = match {
            let mut request = client.get(uri);
            if c.timeout.is_some() {
                request = request.timeout(c.timeout.unwrap())
            }
            request
                .header(header::USER_AGENT, "JoelLinn/acme-proxy")
                .send()
                .await
        }
        {
            Ok(r) => r,
            Err(e) => return Err(error::ErrorBadGateway(e)),
        };

    match proxied_response.status() {
        StatusCode::NOT_FOUND => return Err(error::ErrorNotFound("Not found.")),
        StatusCode::OK => (),
        s => return Err(error::ErrorBadGateway(format!("Server responded with status code {}.", s))),
    };

    let auth_key = std::str::from_utf8(&proxied_response.body().await?)?.trim().to_owned();
    info!("Got auth key '{}' for token '{}' on host '{}'.", auth_key, token, host);

    // check if the authorization is valid
    let re_auth = Regex::new(&format!(r"^{}\.{}", token, "[A-Za-z0-9_-]{43,100}$")).unwrap();
    if !re_auth.is_match(&auth_key) {
        return Err(error::ErrorBadGateway("Server responded with invalid key authorization."))
    }

    Ok(HttpResponse::Ok()
        .set_header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .set_header(header::SERVER, "JoelLinn/acme-proxy")
        .body(auth_key)
    )
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    {
        let mut builder = env_logger::builder();
        match std::env::var_os("RUST_LOG") {
            Some(_) => &mut builder,
            None => builder
                .filter_level(log::LevelFilter::Info)
                .filter(Some("actix_web"), log::LevelFilter::Debug)
        }.init();
    }

    let matches = clap::App::new("ACME Proxy")
        .version(clap::crate_version!())
        .arg(
            clap::Arg::with_name("legal_hosts")
                .takes_value(true)
                .long("legal_hosts")
                .value_name("LEGAL_HOSTS")
                .default_value("^.*$")
                .help("Regex to filter proxied hosts.")
                .required(false),
        )
        .arg(
            clap::Arg::with_name("timeout")
                .takes_value(true)
                .long("timeout")
                .value_name("TIMEOUT")
                .help("Timeout for proxied request in milliseconds.")
                .required(false),
        )
        .get_matches();

    info!("ACME Proxy {}", clap::crate_version!());

    HttpServer::new(move || {
        App::new()
            .data(Client::new())
            .data(ProxyConf {
                re_valid_host: Regex::new(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$").unwrap(),
                re_legal_host: Regex::new(matches.value_of("legal_hosts").unwrap()).unwrap(),
                timeout: matches.value_of("timeout")
                    .and_then(|t| Some(t.parse::<u64>().unwrap()))
                    .and_then(|t| Some(core::time::Duration::from_millis(t)))
            })
            .wrap(actix_web::middleware::Logger::default())
            .route(
                "/.well-known/acme-challenge/{token:[A-Za-z0-9_-]{22,}}",
                web::get().to(proxy))
            .default_service(
                web::route().to(|| HttpResponse::BadRequest()),
            )
    })
    .workers(1)
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
