#[macro_use]
extern crate log;

use actix_http::header;
use actix_web::{
    error, http::StatusCode, web, App, Error, HttpRequest, HttpResponse, HttpServer, Result,
};
use awc::Client;
use regex::Regex;
use std::env;

struct ProxyConf {
    // static stuff initialized once:
    pub re_valid_host: Regex,
    pub re_valid_base64url: Regex,
    // actual config:
    pub re_legal_host: Regex,
    pub timeout: core::time::Duration,
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

    let host = match req
        .headers()
        .get(header::HOST)
        .and_then(|host_value| host_value.to_str().ok())
    {
        Some(s) => s,
        None => return Err(error::ErrorBadRequest("Empty host.")),
    };

    if host == "localhost" || !c.re_valid_host.is_match(host) {
        return Err(error::ErrorBadRequest(format!(
            "Invalid host name: '{}'",
            host
        )));
    }

    // user filter for legal subdomains or list of hosts
    if !c.re_legal_host.is_match(host) {
        return Err(error::ErrorForbidden(format!(
            "Illegal host name: '{}'",
            host
        )));
    }

    let uri = format!("http://{}/.well-known/acme-challenge/{}", host, token);
    info!("Forwarding challenge to '{}'.", uri);

    let mut proxied_response = match {
        client
            .get(uri)
            .timeout(c.timeout)
            .insert_header((header::USER_AGENT, "JoelLinn/acme-proxy"))
            .send()
            .await
    } {
        Ok(r) => r,
        Err(e) => return Err(error::ErrorBadGateway(e)),
    };

    match proxied_response.status() {
        StatusCode::NOT_FOUND => return Err(error::ErrorNotFound("Not found.")),
        StatusCode::OK => (),
        s => {
            return Err(error::ErrorBadGateway(format!(
                "Server responded with status code {}.",
                s
            )))
        }
    };

    let mut auth_key = match std::str::from_utf8(&proxied_response.body().await?) {
        Ok(s) => s,
        Err(e) => {
            warn!("Could not convert server response to utf8: {}", e);
            return Err(error::ErrorBadGateway(
                "Could not convert server response to utf8.",
            ));
        }
    }
    .trim()
    .to_owned();
    info!(
        "Got auth key '{}' for token '{}' on host '{}'.",
        auth_key, token, host
    );

    // check if the authorization is valid
    let auth_len = auth_key.len() - (token.len() + 1);
    if (auth_len < 43)
        || (auth_len > 100)
        || !auth_key.starts_with(token)
        || (auth_key.as_bytes()[token.len()] != b'.')
        || match auth_key.get((token.len() + 1)..) {
            Some(s) => !c.re_valid_base64url.is_match(s),
            None => true,
        }
    {
        return Err(error::ErrorBadGateway(
            "Server responded with invalid key authorization.",
        ));
    }

    auth_key.push('\n');
    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/plain; charset=utf-8"))
        .insert_header((header::SERVER, "JoelLinn/acme-proxy"))
        .body(auth_key))
}

fn env_or(k: &str, default: &str) -> String {
    env::var_os(k)
        .and_then(|v| v.into_string().ok())
        .unwrap_or(default.to_string())
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    {
        let mut builder = env_logger::builder();
        match std::env::var_os("RUST_LOG") {
            Some(_) => &mut builder,
            None => builder
                .filter_level(log::LevelFilter::Info)
                .filter(Some("actix_web"), log::LevelFilter::Debug),
        }
        .init();
    }

    let default_legal_hosts = env_or("ACME_LEGAL_HOSTS", "^.*$");
    let default_timeout = env_or("ACME_TIMEOUT", "1000");
    let matches = clap::Command::new("ACME Proxy")
        .version(clap::crate_version!())
        .arg(
            clap::Arg::new("legal_hosts")
                .num_args(1)
                .long("legal_hosts")
                .value_name("LEGAL_HOSTS")
                .default_value(&default_legal_hosts)
                .help("Regex to filter proxied hosts.")
                .required(false),
        )
        .arg(
            clap::Arg::new("timeout")
                .num_args(1)
                .long("timeout")
                .value_name("TIMEOUT")
                .default_value(&default_timeout)
                .help("Timeout for proxied request in milliseconds.")
                .required(false),
        )
        .get_matches();

    let conf_re_legal_hosts =
        match Regex::new(matches.get_one::<String>("legal_hosts").unwrap().as_str()) {
            Ok(r) => r,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        };
    let conf_timeout = {
        let opt = matches.get_one::<String>("timeout").map(|s| s.as_str());
        match opt.and_then(|t| t.parse::<u64>().ok()) {
            Some(t) => core::time::Duration::from_millis(t),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Invalid timeout value '{}'.", opt.unwrap_or("")),
                ))
            }
        }
    };

    let proxy_conf = web::Data::new( ProxyConf {
        re_valid_host: Regex::new(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$").unwrap(),
        re_valid_base64url: Regex::new(r"^[A-Za-z0-9_-]*$").unwrap(),
        re_legal_host: conf_re_legal_hosts,
        timeout: conf_timeout,
    });

    info!("ACME Proxy {}", clap::crate_version!());

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(Client::new()))
            .app_data(proxy_conf.clone())
            .wrap(actix_web::middleware::Logger::default())
            .route(
                "/.well-known/acme-challenge/{token:[A-Za-z0-9_-]{22,}}",
                web::get().to(proxy),
            )
            .default_service(web::route().to(|| HttpResponse::BadRequest()))
    })
    .workers(1)
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
