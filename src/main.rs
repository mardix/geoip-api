// Copyright 2019 Federico Fissore
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate serde_derive;

use env_logger;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::{Arc, RwLock};

use actix_cors::Cors;
use actix_web::http::HeaderMap;
use actix_web::web;
use actix_web::App;
use actix_web::HttpRequest;
use actix_web::Responder;
use actix_web::HttpServer;
use maxminddb::geoip2::City;
use serde_json;
use std::net::SocketAddr;
use structopt::StructOpt;
use geoipupdate::MaxMindReader;

mod geoipupdate;

#[derive(StructOpt, Debug, Clone)]
struct Options {
    #[structopt(
        short,
        long,
        env = "GEOIP_RS_LISTEN_ADDR",
        default_value = "127.0.0.1:3000"
    )]
    listen_addr: SocketAddr,
    #[structopt(long, env = "GEOIP_RS_UPDATE_MINUTES", default_value = "30")]
    update_minutes: u64,
    #[structopt(long, env = "GEOIP_RS_ACCOUNT_ID")]
    account_id: String,
    #[structopt(long, env = "GEOIP_RS_LICENSE_KEY")]
    license_key: String,
    #[structopt(long, env = "GEOIP_RS_EDITION_ID", default_value = "GeoIP2-City")]
    edition_id: String,
}

#[derive(Serialize)]
struct NonResolvedIPResponse<'a> {
    pub ip_address: &'a str,
    pub error: &'a str
}

#[derive(Serialize)]
struct ResolvedIPResponse<'a> {
    pub ip_address: &'a str,
    pub latitude: &'a f64,
    pub longitude: &'a f64,
    pub postal_code: &'a str,
    pub continent_code: &'a str,
    pub continent_name: &'a str,
    pub country_code: &'a str,
    pub country_name: &'a str,
    pub region_code: &'a str,
    pub region_name: &'a str,
    pub province_code: &'a str,
    pub province_name: &'a str,
    pub city_name: &'a str,
    pub timezone: &'a str,
}

#[derive(Deserialize, Debug)]
struct QueryParams {
    ip: Option<String>,
    lang: Option<String>,
    callback: Option<String>,
}

fn ip_address_to_resolve(
    ip: Option<String>,
    headers: &HeaderMap,
    remote_addr: Option<&str>,
) -> String {
    ip.filter(|ip_address| {
        ip_address.parse::<Ipv4Addr>().is_ok() || ip_address.parse::<Ipv6Addr>().is_ok()
    })
    .or_else(|| {
        headers
            .get("X-Real-IP")
            .map(|s| s.to_str().unwrap().to_string())
    })
    .or_else(|| {
        remote_addr
            .map(|ip_port| ip_port.split(':').take(1).last().unwrap())
            .map(|ip| ip.to_string())
    })
    .expect("unable to find ip address to resolve")
}

fn get_language(lang: Option<String>) -> String {
    lang.unwrap_or_else(|| String::from("en"))
}

struct Db {
    db: Arc<RwLock<MaxMindReader>>,
}

async fn index(
    req: HttpRequest,
    data: web::Data<Db>,
    web::Query(query): web::Query<QueryParams>,
) -> impl Responder {
    let language = get_language(query.lang);
    let ip_address = ip_address_to_resolve(query.ip, req.headers(), req.connection_info().remote());

    let db_opt = data.db.as_ref().read().unwrap();
    let lookup: Result<City, Box<dyn std::error::Error>> = if let Some(db) = &*db_opt {
        db.lookup(ip_address.parse().unwrap())
            .map_err(|e| format!("Could not query maxmind database: {}", e).into())
    } else {
        Err("Maxmind database not found".into())
    };

    match lookup {
        Ok(geoip) => {
            let region = geoip
                .subdivisions
                .as_ref()
                .filter(|subdivs| !subdivs.is_empty())
                .and_then(|subdivs| subdivs.get(0));

            let province = geoip
                .subdivisions
                .as_ref()
                .filter(|subdivs| subdivs.len() > 1)
                .and_then(|subdivs| subdivs.get(1));

            let res = ResolvedIPResponse {
                ip_address: &ip_address,
                latitude: geoip
                    .location
                    .as_ref()
                    .and_then(|loc| loc.latitude.as_ref())
                    .unwrap_or(&0.0),
                longitude: geoip
                    .location
                    .as_ref()
                    .and_then(|loc| loc.longitude.as_ref())
                    .unwrap_or(&0.0),
                postal_code: geoip
                    .postal
                    .as_ref()
                    .and_then(|postal| postal.code.as_ref())
                    .map(String::as_str)
                    .unwrap_or(""),
                continent_code: geoip
                    .continent
                    .as_ref()
                    .and_then(|cont| cont.code.as_ref())
                    .map(String::as_str)
                    .unwrap_or(""),
                continent_name: geoip
                    .continent
                    .as_ref()
                    .and_then(|cont| cont.names.as_ref())
                    .and_then(|names| names.get(&language))
                    .map(String::as_str)
                    .unwrap_or(""),
                country_code: geoip
                    .country
                    .as_ref()
                    .and_then(|country| country.iso_code.as_ref())
                    .map(String::as_str)
                    .unwrap_or(""),
                country_name: geoip
                    .country
                    .as_ref()
                    .and_then(|country| country.names.as_ref())
                    .and_then(|names| names.get(&language))
                    .map(String::as_str)
                    .unwrap_or(""),
                region_code: region
                    .and_then(|subdiv| subdiv.iso_code.as_ref())
                    .map(String::as_ref)
                    .unwrap_or(""),
                region_name: region
                    .and_then(|subdiv| subdiv.names.as_ref())
                    .and_then(|names| names.get(&language))
                    .map(String::as_ref)
                    .unwrap_or(""),
                province_code: province
                    .and_then(|subdiv| subdiv.iso_code.as_ref())
                    .map(String::as_ref)
                    .unwrap_or(""),
                province_name: province
                    .and_then(|subdiv| subdiv.names.as_ref())
                    .and_then(|names| names.get(&language))
                    .map(String::as_ref)
                    .unwrap_or(""),
                city_name: geoip
                    .city
                    .as_ref()
                    .and_then(|city| city.names.as_ref())
                    .and_then(|names| names.get(&language))
                    .map(String::as_str)
                    .unwrap_or(""),
                timezone: geoip
                    .location
                    .as_ref()
                    .and_then(|loc| loc.time_zone.as_ref())
                    .map(String::as_str)
                    .unwrap_or(""),
            };
            serde_json::to_string(&res)
        }
        Err(e) => serde_json::to_string(&NonResolvedIPResponse {
            ip_address: &ip_address,
            error: &e.to_string()
        }),
    }
    .unwrap()
}

#[actix_rt::main]
async fn main() {
    env_logger::init();
    let opt = Options::from_args();
    let listen_addr = opt.listen_addr;

    println!("Listening on http://{}", listen_addr);

    let db = Arc::new(RwLock::new(None));

    let updater = geoipupdate::GeoIPUpdater::new(
        opt.update_minutes,
        db.clone(),
        opt.account_id,
        opt.license_key,
        opt.edition_id,
    );
    updater.start();

    HttpServer::new(move || {
        App::new()
            .data(Db { db: db.clone() })
            .wrap(Cors::new().send_wildcard().finish())
            .route("/", web::route().to(index))
    })
    .bind(opt.listen_addr)
    .unwrap_or_else(|_| panic!("Can not bind to {}", listen_addr))
    .run()
    .await
    .unwrap();
}
