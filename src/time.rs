extern crate chrono;            // DateTime manipulation

use crate::mutate::*;
use chrono::offset::Utc;

// get the current date time
pub fn get_now() -> Result<String, std::io::Error>  {
    Ok(format_date(Utc::now())?)
}

// used to initialize a date time to epoch start
pub fn get_epoch_start() -> String  {
    "1970-01-01 00:00:00.000".to_string()
}