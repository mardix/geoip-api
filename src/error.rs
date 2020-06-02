use actix_web::{http::StatusCode, ResponseError};
use maxminddb::MaxMindDBError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GeoIPError {
    #[error("Could not unlock geoip database")]
    PoisonError,
    #[error("GeoIP Database Not Found")]
    DatabaseNotFound,
    #[error("Could not parse given IP")]
    ParseError,
    #[error(transparent)]
    MaxMindError(#[from] MaxMindDBError),
}
impl ResponseError for GeoIPError {
    fn status_code(&self) -> StatusCode {
        match self {
            GeoIPError::ParseError => StatusCode::BAD_REQUEST,
            GeoIPError::MaxMindError(MaxMindDBError::AddressNotFoundError(_)) => {
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
