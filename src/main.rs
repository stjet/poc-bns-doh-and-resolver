use std::path::PathBuf;
use std::convert::Infallible;

use rocket::{ get, options, post, Request, Responder };
use rocket::response::Redirect;
use rocket::response::content::RawHtml;
use rocket::http::{ ContentType, Header };
use rocket::request::{ FromRequest, Outcome };
use rocket::shield::{ Shield, Hsts };
use rocket::routes;

mod utils;
use crate::utils::extract_tld;
mod dns;
use crate::dns::{ answer_dns_query, do_dns_query_for_bns, Answer, QueryResult, SELF_HOST };

struct Host {
  pub host: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Host {
  type Error = Infallible;

  async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
    match request.host() {
      Some(host) => {
        Outcome::Success(Host { host: host.to_string() })
      },
      //whatever, man
      None => Outcome::Success(Host { host: SELF_HOST.to_string() })
    }
  }
}

#[derive(Responder)]
enum MaybeRedirect<R> {
  RawHtml(RawHtml<R>),
  Redirect(Redirect),
}

async fn handle_redirect(path: Option<PathBuf>, host: Host) -> MaybeRedirect<&'static str> {
  let host = host.host;
  println!("HOST {}", host);
  if host == SELF_HOST {
    MaybeRedirect::RawHtml(RawHtml(r#"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>BNS DoH Server</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
  </head>
  <body>
    <h1>Hello, world! This is the BNS DoH POC.</h1>
    <p>Set the DoH URL in your browser's settings to <code>https://127.0.0.1/dns-query</code>. Then try going to <a href="http://prussia.ban">http://prussia.ban</a> and <a href="https://prussia.ban.k">https://prussia.ban.k</a></p>
  </body>
</html>"#))
  } else {
    let (domain_name, tld) = extract_tld(&host);
    //todo: instead of unwrap_or(0) should reject the request or something
    MaybeRedirect::Redirect(if let QueryResult::A(_, Some(redirect)) = do_dns_query_for_bns(domain_name.to_string(), tld.to_string()).await {
      //todo: add path
      Redirect::to(redirect)
    } else {
      //failed
      Redirect::to(format!("http://{}", SELF_HOST))
    })
  }
}

#[get("/")]
async fn handle_redirect_1(host: Host) -> MaybeRedirect<&'static str> {
  handle_redirect(None, host).await
}

#[get("/<path..>")]
async fn handle_redirect_2(path: PathBuf, host: Host) -> MaybeRedirect<&'static str> {
  handle_redirect(Some(path), host).await
}

#[derive(Responder)]
#[response(status = 200)]
struct DnsOptions {
  content_type: (ContentType, ()),
  accept: Header<'static>,
}

#[options("/dns-query")]
fn handle_dns_options() -> DnsOptions {
  DnsOptions {
    content_type: (ContentType::new("application", "dns-message"), ()),
    accept: Header::new("Accept", "application/dns-message"),
  }
}

#[get("/dns-query?<dns>")]
async fn handle_dns_get(dns: &str) -> Answer {
  if let Ok(u8_vec) = utils::b64_url_to_u8_vec(dns) {
    answer_dns_query(u8_vec, 0).await
  } else {
    //error parsing the b64
    Answer { bytes: None }
  }
}

#[post("/dns-query", format = "application/dns-message", data = "<dns>")]
async fn handle_dns_post(dns: Vec<u8>) -> Answer {
  answer_dns_query(dns, 0).await
}

#[rocket::launch]
async fn rocket() -> _ {
  //let shield = Shield::default().disable::<Hsts>();
  let shield = Shield::new();
  rocket::build().attach(shield).mount("/", routes![
    handle_redirect_1,
    handle_redirect_2,
    handle_dns_options,
    handle_dns_get,
    handle_dns_post,
  ])
}

//https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/
