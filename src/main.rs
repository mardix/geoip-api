#[macro_use]
extern crate serde_derive;

use actix_cors::Cors;
use actix_web::{web, App, HttpRequest, HttpServer};
use actix_web_prom::PrometheusMetrics;

use env_logger;
use geoipupdate::MaxMindReader;
use maxminddb::geoip2::City;
use prometheus::{opts, IntCounter, IntGauge};

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use structopt::StructOpt;

use error::GeoIPError;

use geoipupdate::GeoIPUpdater;
use geoipupdate::GeoIPUpdaterMetrics;

mod error;
mod geoipupdate;

#[derive(StructOpt, Debug, Clone)]
struct Options {
    #[structopt(
        short,
        long,
        env = "GEOIP_API_LISTEN_ADDR",
        default_value = "127.0.0.1:3000"
    )]
    listen_addr: SocketAddr,
    #[structopt(long, env = "GEOIP_API_UPDATE_MINUTES", default_value = "30")]
    update_minutes: u64,
    #[structopt(long, env = "GEOIP_API_ACCOUNT_ID")]
    account_id: String,
    #[structopt(long, env = "GEOIP_API_LICENSE_KEY")]
    license_key: String,
    #[structopt(long, env = "GEOIP_API_EDITION_ID", default_value = "GeoIP2-City")]
    edition_id: String,
}

#[derive(Serialize)]
struct ResolvedIPResponse {
    pub ip_address: String,
    pub latitude: f64,
    pub longitude: f64,
    pub postal_code: String,
    pub continent_code: String,
    pub continent_name: String,
    pub country_code: String,
    pub country_name: String,
    pub region_code: String,
    pub region_name: String,
    pub province_code: String,
    pub province_name: String,
    pub city_name: String,
    pub timezone: String,
}

#[derive(Deserialize, Debug)]
struct QueryParams {
    ip: Option<String>,
    lang: Option<String>,
}

fn get_language(lang: Option<String>) -> String {
    lang.unwrap_or_else(|| String::from("en"))
}

struct Db {
    db: Arc<RwLock<MaxMindReader>>,
}

async fn index(
    _req: HttpRequest,
    data: web::Data<Db>,
    web::Query(query): web::Query<QueryParams>,
) -> Result<web::Json<ResolvedIPResponse>, GeoIPError> {
    let language = get_language(query.lang);
    let ip_address = query
        .ip
        .filter(|ip_address| {
            ip_address.parse::<Ipv4Addr>().is_ok() || ip_address.parse::<Ipv6Addr>().is_ok()
        })
        .ok_or(GeoIPError::ParseError)?;

    let db_opt = data
        .db
        .as_ref()
        .read()
        .map_err(|_| GeoIPError::PoisonError)?;

    let geoip: City = if let Some(db) = &*db_opt {
        // we can unwrap here because we parsed previously
        db.lookup(ip_address.parse().unwrap())
    } else {
        Err(GeoIPError::DatabaseNotFound)?
    }?;

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

    Ok(web::Json(ResolvedIPResponse {
        ip_address: ip_address.to_owned(),
        latitude: geoip
            .location
            .as_ref()
            .and_then(|loc| loc.latitude)
            .unwrap_or(0.0),
        longitude: geoip
            .location
            .as_ref()
            .and_then(|loc| loc.longitude)
            .unwrap_or(0.0),
        postal_code: geoip
            .postal
            .as_ref()
            .and_then(|postal| postal.code.clone())
            .unwrap_or("".to_owned()),
        continent_code: geoip
            .continent
            .as_ref()
            .and_then(|cont| cont.code.clone())
            .unwrap_or("".to_owned()),
        continent_name: geoip
            .continent
            .as_ref()
            .and_then(|cont| cont.names.as_ref())
            .and_then(|names| names.get(&language).cloned())
            .unwrap_or("".to_owned()),
        country_code: geoip
            .country
            .as_ref()
            .and_then(|country| country.iso_code.clone())
            .unwrap_or("".to_owned()),
        country_name: geoip
            .country
            .as_ref()
            .and_then(|country| country.names.as_ref())
            .and_then(|names| names.get(&language).cloned())
            .unwrap_or("".to_owned()),
        region_code: region
            .and_then(|subdiv| subdiv.iso_code.clone())
            .unwrap_or("".to_owned()),
        region_name: region
            .and_then(|subdiv| subdiv.names.as_ref())
            .and_then(|names| names.get(&language).cloned())
            .unwrap_or("".to_owned()),
        province_code: province
            .and_then(|subdiv| subdiv.iso_code.clone())
            .unwrap_or("".to_owned()),
        province_name: province
            .and_then(|subdiv| subdiv.names.as_ref())
            .and_then(|names| names.get(&language).cloned())
            .unwrap_or("".to_owned()),
        city_name: geoip
            .city
            .as_ref()
            .and_then(|city| city.names.as_ref())
            .and_then(|names| names.get(&language).cloned())
            .unwrap_or("".to_owned()),
        timezone: geoip
            .location
            .as_ref()
            .and_then(|loc| loc.time_zone.clone())
            .unwrap_or("".to_owned()),
    }))
}

async fn health(_req: HttpRequest, data: web::Data<Db>) -> Result<&'static str, GeoIPError> {
    let db_opt = data
        .db
        .as_ref()
        .read()
        .map_err(|_| GeoIPError::PoisonError)?;

    if let Some(_db) = &*db_opt {
        Ok("OK")
    } else {
        Err(GeoIPError::DatabaseNotFound)?
    }
}

#[actix_rt::main]
async fn main() {
    env_logger::init();
    let opt = Options::from_args();
    let listen_addr = opt.listen_addr;

    let prometheus = PrometheusMetrics::new("geoip", Some("/metrics"), None);

    let last_updated_opts = opts!(
        "database_last_updated",
        "timestamp of the last time the geoip database was modified"
    )
    .namespace("geoip");
    let last_updated = IntGauge::with_opts(last_updated_opts).unwrap();

    let last_checked_opts = opts!(
        "database_last_checked",
        "timestamp of the last time an update was checked for the geoip database"
    )
    .namespace("geoip");
    let last_checked = IntGauge::with_opts(last_checked_opts).unwrap();

    let error_count_opts = opts!(
        "geoip_update_errors",
        "number of errors fetching the geoip database"
    )
    .namespace("geoip");
    let error_count = IntCounter::with_opts(error_count_opts).unwrap();

    prometheus
        .registry
        .register(Box::new(last_updated.clone()))
        .unwrap();

    prometheus
        .registry
        .register(Box::new(last_checked.clone()))
        .unwrap();

    prometheus
        .registry
        .register(Box::new(error_count.clone()))
        .unwrap();

    let db = Arc::new(RwLock::new(None));

    let updater_metrics = GeoIPUpdaterMetrics::new(
        last_updated.clone(),
        last_checked.clone(),
        error_count.clone(),
    );

    let updater = GeoIPUpdater::new(
        opt.update_minutes,
        db.clone(),
        opt.account_id,
        opt.license_key,
        opt.edition_id,
        updater_metrics,
    );
    updater.start();

    println!("Listening on http://{}", listen_addr);

    HttpServer::new(move || {
        App::new()
            .data(Db { db: db.clone() })
            .wrap(Cors::new().send_wildcard().finish())
            .wrap(prometheus.clone())
            .route("/", web::route().to(index))
            .route("/health", web::route().to(health))
    })
    .bind(opt.listen_addr)
    .unwrap_or_else(|_| panic!("Can not bind to {}", listen_addr))
    .run()
    .await
    .unwrap();
}
