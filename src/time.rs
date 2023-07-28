extern crate chrono;            // DateTime manipulation

use crate::mutate::*;
use std::io::Error;
use chrono::*;
use crate::data_defs::*;

// get the current date time
pub fn get_now() -> Result<String, std::io::Error>  {
    Ok(format_date(Utc::now())?)
}

// used to initialize a date time to epoch start
pub fn get_epoch_start() -> String  {
    "1970-01-01T00:00:00.000Z".to_string()
}

// convert string to utc datetime
// pub fn to_utc_datetime(time: &str) -> Result<DateTime::<Utc>, Error>  
// {
//     let _: DateTime<Utc> = match Utc.datetime_from_str(time, "%Y-%m-%dT%H:%M:%S.%3f") {
//         Ok(t) => return Ok(t),
//         Err(_e) => return Ok(*TIME_END)
//     };
// }

fn to_utc_datetime(time: &str) -> DateTime::<Utc> {
    match DateTime::parse_from_rfc3339(time) {
        Ok(datetime) => {
            let datetime = datetime.with_timezone(&Utc);
            return datetime
        }
        Err(e) => {
            return *TIME_END
        }
    }
}

// is the datetime within the time window we are examining?
pub fn in_time_window(time: &str) -> Result<bool, Error>  
{
    // convert time for comparision to time window start and end
    let t = to_utc_datetime(time);

    if TIME_START.le(&t) && TIME_END.gt(&t) {
        Ok(true)
    } else {
        Ok(false)
    }
}