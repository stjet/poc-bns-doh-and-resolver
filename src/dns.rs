use std::collections::HashMap;
use std::io::Cursor;

use rocket::Response;
use rocket::response;
use rocket::response::Responder;
use rocket::http::Status;
use rocket::request::Request;

use serde::{ Serialize, Deserialize };

use reqwest::Client;
use reqwest::header::{ HeaderMap, ACCEPT, CONTENT_TYPE };

use crate::utils::*;

//https://dns.elintra.net/dns-query

//pub const SELF_CNAME: &'static str = "dns.elintra.net";
pub const SELF_HOST: &'static str = "127.0.0.1";
pub const SELF_IP: [u8; 4] = [127, 0, 0, 1];
/*
 * - https://query.hdns.io/dns-query
 * - https://dns.mullvad.net/dns-query 
*/
const NON_BNS_DOH: &'static str = "https://mozilla.cloudflare-dns.com/dns-query";
const BNS_API: &'static str = "https://api.creeper.banano.cc/banano/v1/account/bns";
const IPFS_API: &'static str = "https://ipfs.oversas.org/ipfs/";
const TLDS: [&'static str; 3] = ["mictest", "ban", "jtv"];

//rfc 1035 (section 4, section 7.3)
//rfc 8484
//www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat-2.htm

//16 bits (2 bytes)
/*
fn extract_type_bytes_from_dns_query(dns_query: &[u8]) -> u16 {
  //
  let length = dns_query[12];
  if length >= 192 {
    ((dns_query[13] as u16) << 8) | (dns_query[14] as u16)
  } else {
    ((dns_query[12 + length as usize] as u16) << 8) | (dns_query[12 + length as usize + 1] as u16)
  }
}
*/

pub struct Answer {
  pub bytes: Option<Vec<u8>>,
}

impl<'r> Responder<'r, 'static> for Answer {
  fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
    if let Some(rb) = self.bytes {
      println!("a {:?}", &rb);
      Response::build().status(Status { code: 200 }).raw_header("Content-Type", "application/dns-message").raw_header("Accept", "application/dns-message").sized_body(rb.len(), Cursor::new(rb)).ok()
    } else {
      Response::build().status(Status { code: 400 }).ok()
    }
  }
}

#[derive(Serialize)]
struct BnsApiPayload {
  domain_name: String,
  tld: String,
}

#[derive(Deserialize)]
pub struct BnsApiDomain {
  tld: String,
  name: String,
  #[serde(skip)]
  history: Vec<String>, //should really be a vec of history blocks
  burned: Option<bool>,
  metadata_hash: Option<String>,
  resolved_address: Option<String>,
}

#[derive(Deserialize)]
pub struct BnsApiResponse {
  domain: BnsApiDomain,
}

pub struct BnsDomain {
  pub api_domain: BnsApiDomain,
  pub metadata: HashMap<String, String>,
}

pub enum QueryResult {
  Cname(String),
  A([u8; 4], Option<String>),
  NXDomain,
  NonBns,
}

//start param is a different index to start at (used for pointers)
pub fn extract_host_from_dns_query(dns_query: &[u8], start: Option<usize>) -> Result<String, ()> {
  //13th byte should be start of question, indicate how long the label/zone is in bytes
  let mut length_pos: usize = 12;
  if start.is_some() {
    length_pos = start.unwrap();
  }
  let mut domain_name: Vec<String> = Vec::new();
  let query_len = dns_query.len();
  loop {
    if length_pos >= query_len {
      return Err(());
    }
    let length = dns_query[length_pos];
    if length_pos + usize::from(length) >= dns_query.len() {
      return Err(());
    }
    if length == 0 {
      //the last ., ended
      break;
    }
    let label;
    if length >= 192 {
      //first two bits are 11, is pointer
      let offset: usize = binary_to_u8(&to_binary(length, false)[2..]).into();
      label = extract_host_from_dns_query(dns_query, Some(offset))?;
    } else {
      //ascii
      let label_bytes = &dns_query[(length_pos + 1)..=(length_pos + usize::from(length))];
      label = label_bytes.iter().map(|c_u8| char::from(c_u8.clone()).to_string()).collect::<Vec<String>>().join("");
    }
    domain_name.push(label);
    length_pos = length_pos + usize::from(length) + 1;
  }
  return Ok(domain_name.join("."));
}

pub fn query_hostname_to_label_bytes(query_hostname: &str) -> Vec<u8> {
  let mut label_bytes = Vec::new();
  //length
  //error if too long?
  //
  for label in query_hostname.split(".") {
    label_bytes.push(label.len() as u8);
    for c in label.chars() {
      //convert to ascii
      label_bytes.push(c as u8);
    }
  }
  label_bytes.push(0);
  label_bytes
}

async fn bns_domain_api(domain_name: String, tld: String) -> reqwest::Result<BnsDomain> {
  let client = Client::new();
  let api_domain = (client.post(BNS_API).json(&BnsApiPayload {
    domain_name,
    tld,
  }).send().await?.json::<BnsApiResponse>().await?).domain;
  let mut metadata = HashMap::new();
  if let Some(ref metadata_hash) = api_domain.metadata_hash {
    metadata = client.get(&format!("{}{}", IPFS_API, metadata_hash)).send().await?.json::<HashMap<String, String>>().await?;
  }
  Ok(BnsDomain {
    api_domain,
    metadata,
  })
}

pub async fn do_dns_query_for_bns(domain_name: String, tld: String) -> QueryResult {
  if let Ok(result) = bns_domain_api(domain_name, tld).await {
    /*In order, look for:
    - "A" record
    - "CNAME" record
    - "redirect" (Cname to self, redirect to specified)
    - "resolved_address" (Cname to self, redirect to creeper)
    */
    if let Some(a_record) = result.metadata.get("A") {
      if let Some(a) = parse_a_record(a_record) {
        return QueryResult::A(a, None);
      }
    }
    if let Some(cname_record) = result.metadata.get("CNAME") {
      return QueryResult::Cname(cname_record.to_string());
    }
    if let Some(redirect) = result.metadata.get("redirect") {
      return QueryResult::A(SELF_IP, Some(redirect.to_string()));
    }
    if let Some(resolved_address) = result.api_domain.resolved_address {
      return QueryResult::A(SELF_IP, Some(format!("https://creeper.banano.cc/account/{}", resolved_address)));
    }
    QueryResult::NXDomain
  } else {
    QueryResult::NXDomain
  }
}

async fn do_internal_dns_query(host: &str) -> QueryResult {
  let (domain_name, tld) = extract_tld(&host);
  if TLDS.contains(&tld) {
    //todo: be better
    do_dns_query_for_bns(domain_name.to_string(), tld.to_string()).await
  } else {
    QueryResult::NonBns
  }
}

pub async fn answer_dns_query(dns_query: Vec<u8>, nested: usize) -> Answer {
  if nested > 2 {
    return Answer { bytes: None };
  }
  let client = Client::new();
  //Identification (not needed for DoH, should be 0), 16 bits
  /*
  Flags (total 16 bits)
  QR (query: 0, reply: 1), 1 bit
  OPCODE (standard: 0, inverse: 1, status: 2), 4 bits (opcode in query is repeated in response)
  AA (if authorative answer for hostname), 1 bit
  TC (whether message was truncated), 1 bit
  RD (where recursion desired), 1 bit
  RA (in response, whether recursion available), 1 bit
  Z (reserved), 3 bits
  RCODE (response code, NOERROR: 0, FORM(at)ERR: 1, SERVFAIL: 2, NXDOMAIN: 3), 4 bits
  */
  //# of questions, 16 bits
  //# of answers (response), 16 bits
  //# of authority resource records (aka RR), 16 bits
  //# of additional RRs, 16 bits
  //so above is 12 bytes

  //what the first 12 bytes will be for a regular response (4th [0 -> 3] and 8th [1 -> 0] byte will be different for NXDOMAIN, similar for SERVFAIL)
  //Id: 0, 0. Flags: 1 0000 0 0 0, 0 000 0000 (or 0011 for NXDOMAIN, 0010 for SERVFAIL). # of q: 0, 1 (question in query apparently needs to be copied to response). # of a: 0 1 (0 if NXDOMAIN, SERVFAIL). # of aurr: 0 0. # of adrr: 0 0.
  //ok so above is 128 0 but everyone seems to be doing 129 128 (see flags above)
  //we do 129 0, indicating we do not support recursion, forcing the browser to resolve the cname
  let mut resp_start_bytes: Vec<u8> = vec![0, 0, 129, 0, 0, 1, 0, 1, 0, 0, 0, 0];
  //let mut dns_query: Vec<u8> = vec![0, 0, 1, 128, 0, 1, 0, 0, 0, 0, 0, 0];
  /*
  Question section
  Can have many questions, but in practice most only allow 1. so we will do same, plus its easier (see "# of questions" field)
  IMPORTANT: the question in the query is apparently COPIED TO THE RESPONSE too, so response's QDCOUNT will be 1 and contain the question
  Format:
  NAME, variable length
  - NAME is divided into multiple zones/labels (eg: en, wikipedia, org), each zone has 8 bits indicating how many bytes the length is (eg, en is 2 bytes), then the name in ascii, repeated), 0 indicates the NAME is done. Eg: 2 en 9 wikipedia 3 org 0
  - labels start with 00
  - labels start with length of label
  - NAME or a zone can also be a pointer (16 bits) if first two bits are 11, other 14 bits are an offset
  TYPE (of question. A, AAAA, MX, TXT, or special from 251-255, 255 is * [all records]), 16 bits
  CLASS (probably IN for internet), 16 bits
  */
  /*
  Answer section
  Can have many answer, but in our case only one (see "# of answers" field)
  RR Format:
  NAME, variable length (see above in question section)
  TYPE (A, AAAA, MX, TXT, etc), 16 bits
  CLASS, 16 bits
  TTL (time record is valid for), 32 bits
  RDLENGTH (length of RDATA in bytes), 16 bits
  RDATA (additional RR specific data, see RDLENGTH), variable length
  */
  //Authority section: RRs that point toward authority (NOT RELEVANT for us)
  //Additional space section: RRs with additional information (NOT RELEVANT for us)
  //first do some sanity checks, extract ID (should be 0 but w/e), make sure is query
  //also only accept if one question (pretty sure no one does multiple nowadays anyways)
  //also check length
  //TODO
  //
  //println!("q: {:?}", dns_query);
  //extract the host name
  let query_host_wrapped = extract_host_from_dns_query(&dns_query, None);
  if let Ok(query_host) = query_host_wrapped {
    println!("\nRequested: {}\n", query_host);
    println!("q {} {:?}", query_host, dns_query);
    //now actual dns query stuff, and http response
    match do_internal_dns_query(&query_host).await {
      QueryResult::Cname(cname) => {
        //cname
        //firefox, at least, never asks directly for cname, so we return as additional record?
        let mut host_label_bytes = query_hostname_to_label_bytes(&query_host);
        let qtype = dns_query[12 + host_label_bytes.len() + 1];
        //append question to resp_start_bytes (yes, this is a response, but question needs to be copied from query, apparently)
        //label
        resp_start_bytes.append(&mut host_label_bytes);
        //type and class are whatever the qtype is and IN (1)
        resp_start_bytes.extend_from_slice(&[0 as u8, qtype]);
        resp_start_bytes.extend_from_slice(&[0 as u8, 1 as u8]);
        //append answer to resp_start_bytes
        //offset to the label in the front
        resp_start_bytes.extend_from_slice(&[192 as u8, 12 as u8]);
        //resp_start_bytes.append(&mut query_hostname_to_label_bytes(&query_host));
        //type and class are CNAME (5) and IN (1)
        resp_start_bytes.extend_from_slice(&[0 as u8, 5 as u8]);
        resp_start_bytes.extend_from_slice(&[0 as u8, 1 as u8]);
        //TTL (arbitrarily pick 10 minutes, or 600 seconds [0x0258])
        resp_start_bytes.extend_from_slice(&[0 as u8, 0 as u8, 2 as u8, 88 as u8]);
        let label_bytes = query_hostname_to_label_bytes(&cname);
        //RD LENGTH is two bytes
        resp_start_bytes.push(0);
        resp_start_bytes.push(label_bytes.len().try_into().unwrap());
        //RDDATA
        resp_start_bytes.extend_from_slice(&label_bytes);
        //recursively resolve CNAME, no longer needed since we tell the client we don't recurse
        /*if qtype == 5 {
          //question is 1, answer is 0
          let mut question: Vec<u8> = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
          question.extend(query_hostname_to_label_bytes(&cname));
          question.extend([0, 1, 0, 1]); //A (1) and IN (1)
          if let Some(nested_rb) = &Box::pin(answer_dns_query(dns_query, nested + 1)).await.bytes {
            let ans = resp_start_bytes[7];
            resp_start_bytes[7] += ans;
            let mut ni = nested_rb.iter();
            for _ in 0..ans {
              //
            }
          }
        }*/
        Answer { bytes: Some(resp_start_bytes) }
      },
      QueryResult::A(ip, _) => {
        //TODO: make sure question type is all records (255) or A (1) (unrelated, CNAME is 5),
        //extract_type_bytes_from_dns_query?
        //
        //construct response
        //append question to resp_start_bytes (yes, this is a response, but question needs to be copied from query, apparently)
        //label
        resp_start_bytes.append(&mut query_hostname_to_label_bytes(&query_host));
        //type and class are A (1) and IN (1)
        resp_start_bytes.extend_from_slice(&[0 as u8, 1 as u8]);
        resp_start_bytes.extend_from_slice(&[0 as u8, 1 as u8]);
        //append answer to resp_start_bytes
        //offset to the label in the front
        resp_start_bytes.extend_from_slice(&[192 as u8, 12 as u8]);
        //resp_start_bytes.append(&mut query_hostname_to_label_bytes(&query_host));
        //type and class are A (1) and IN (1)
        resp_start_bytes.extend_from_slice(&[0 as u8, 1 as u8]);
        resp_start_bytes.extend_from_slice(&[0 as u8, 1 as u8]);
        //TTL (arbitrarily pick 10 minutes, or 600 seconds [0x0258])
        resp_start_bytes.extend_from_slice(&[0 as u8, 0 as u8, 2 as u8, 88 as u8]);
        //RD LENGTH is two bytes, A record is 4 bytes
        resp_start_bytes.push(0);
        resp_start_bytes.push(4);
        //RDDATA
        resp_start_bytes.extend_from_slice(&ip);
        Answer { bytes: Some(resp_start_bytes) }
      },
      QueryResult::NXDomain => {
        //Not found
        resp_start_bytes[5] = 0; //# of q: 0
        //explanation of below, see above where resp_start_bytes is defined
        resp_start_bytes[2] = 3;
        resp_start_bytes[7] = 0;
        //need to send 200 even if nxdomain, see rfc8484 4.2.1
        Answer { bytes: Some(resp_start_bytes) }
      },
      QueryResult::NonBns => {
        //regular domain, ens or handshake domain
        //hnsdns handles all, how nice. No adblock though, like mullvad...
        //forward query to other DoH, and return what it returns
        let mut header_map = HeaderMap::new();
        header_map.insert(ACCEPT, "application/dns-message".parse().unwrap());
        header_map.insert(CONTENT_TYPE, "application/dns-message".parse().unwrap());
        let try_res = client.post(NON_BNS_DOH).body(dns_query).headers(header_map).send().await; //in the future, throw 500 if fails
        if let Ok(res) = try_res {
          //let res_status = res.status().as_u16(); //todo: status should be 200
          //println!("response from hnsdns: {:?}", res.bytes().unwrap().to_vec());
          let rb = res.bytes().await.unwrap().to_vec();
          Answer { bytes: Some(rb) }
        } else {
          println!("SERVFAIL");
          resp_start_bytes[5] = 0; //# of q: 0
          //should it be a SERVFAIL dns reply?
          resp_start_bytes[2] = 2;
          resp_start_bytes[7] = 0;
          //need to send 200 even if nxdomain, see rfc8484 4.2.1
          Answer { bytes: Some(resp_start_bytes) }
        }
      },
    }
  } else {
    //400 bad request, since could not find host in question section of query
    Answer { bytes: None }
  }
}
