use std::path::PathBuf;
use std::convert::Infallible;

use rocket::{ get, options, post, Request, Responder };
use rocket::response::Redirect;
use rocket::response::content::RawHtml;
use rocket::http::{ ContentType, Header };
use rocket::request::{ FromRequest, Outcome };
use rocket::routes;

mod utils;
use crate::utils::extract_tld;
mod dns;
use crate::dns::{ answer_dns_query, do_dns_query_for_bns, Answer, QueryResult, SELF_CNAME };

struct Host {
  pub host: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Host {
  type Error = Infallible;

  async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
    match request.headers().get_one("Host") {
      Some(host) => {
        Outcome::Success(Host { host: host.to_string() })
      },
      //whatever, man
      None => Outcome::Success(Host { host: SELF_CNAME.to_string() })
    }
  }
}

#[derive(Responder)]
enum MaybeRedirect<R> {
  RawHtml(RawHtml<R>),
  Redirect(Redirect),
}

#[get("/<path..>")]
async fn handle_redirect(path: PathBuf, host: Host) -> MaybeRedirect<&'static str> {
  let host = host.host;
  if host == SELF_CNAME {
    MaybeRedirect::RawHtml(RawHtml(r#"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>BNS DoH Server</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
  </head>
  <body>
    <h1>Hello, world!</h1>
  </body>
</html>"#))
  } else {
    let tld = extract_tld(&host);
    //todo: instead of unwrap_or(0) should reject the request or something
    let domain_name = host[..(host.len() - tld.len()).checked_sub(1).unwrap_or(0)].to_string();
    MaybeRedirect::Redirect(if let QueryResult::Cname(_, Some(redirect)) = do_dns_query_for_bns(domain_name, tld.to_string()).await {
      //todo: add path
      Redirect::to(redirect)
    } else {
      //failed
      Redirect::to(format!("http://{}", SELF_CNAME))
    })
  }
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
  rocket::build().mount("/", routes![
    handle_redirect,
    handle_dns_options,
    handle_dns_get,
    handle_dns_post,
  ])
}

//https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/
