extern crate chrono;            // DateTime manipulation

use chrono::offset::Utc;
use chrono::DateTime;

// get date into the format we need
pub fn format_date(time: DateTime<Utc>) -> Result<String, std::io::Error>  {
    Ok(time.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string())
}

// convert string to i128 or return 0 if fails
pub fn to_int128(num: &str) -> std::io::Result<i128> {
    let n = match num.parse::<i128>() {
        Ok(i) => i,
        Err(_e) => 0
    };
    Ok(n)
}

// convert string to i64 or return 0 if fails
pub fn to_int64(num: &str) -> std::io::Result<i64> {
    let n = match num.parse::<i64>() {
        Ok(i) => i,
        Err(_e) => 0
    };
    Ok(n)
}

// convert string to i32 or return 0 if fails
pub fn to_int32(num: &str) -> std::io::Result<i32> {
    let n = match num.parse::<i32>() {
        Ok(i) => i,
        Err(_e) => 0
    };
    Ok(n)
}

// convert string to i32 or return 0 if fails
/*
pub fn to_int16(num: &str) -> i16 {
    let n = match num.parse::<i16>() {
        Ok(i) => i,
        Err(_e) => 0
    };
    return n
}
*/

// convert string to i8 or return 0 if fails
pub fn to_int8(num: &str) -> std::io::Result<i8> {
    let n = match num.parse::<i8>() {
        Ok(i) => i,
        Err(_e) => 0
    };
    Ok(n)
}

/*
    Convert u128 to IPv6
        Procfs stores IPv6 as individual reversed dwords.
        Therefore have to break the 128bit value into 4 dwords, reverse them and recombine
    See: https://users.rust-lang.org/t/convert-hex-socket-notation-to-ip-and-port/33858/8
*/
pub fn u128_to_ipv6 (mut n: u128) -> std::io::Result<::std::net::Ipv6Addr> {
    unsafe { &mut *(&mut n as *mut u128 as *mut [u32; 4]) }
        .iter_mut()
        .for_each(|n: &mut u32| *n = n.swap_bytes());
    Ok(::std::net::Ipv6Addr::from(n))
}

// translate hex state to human readable
pub fn get_tcp_state(state: &str) -> std::io::Result<String> {
    match state {
        "01" => return Ok("TCP_ESTABLISHED".to_string()),
        "02" => return Ok("TCP_SYN_SENT".to_string()),
        "03" => return Ok("TCP_SYN_RECV".to_string()),
        "04" => return Ok("TCP_FIN_WAIT1".to_string()),
        "05" => return Ok("TCP_FIN_WAIT2".to_string()),
        "06" => return Ok("TCP_TIME_WAIT".to_string()),
        "07" => return Ok("TCP_CLOSE".to_string()),
        "08" => return Ok("TCP_CLOSE_WAIT".to_string()),
        "09" => return Ok("TCP_LAST_ACK".to_string()),
        "0A" => return Ok("TCP_LISTEN".to_string()),
        "0B" => return Ok("TCP_CLOSING".to_string()),    /* Now a valid state */
        "0C" => return Ok("TCP_MAX_STATES".to_string()),  /* Leave at the end! */
        _ => return Ok("UNKNOWN".to_string())
    }
}

// split string on string and return vec
pub fn split_to_vec(source: &str, split_by: &str) -> std::io::Result<Vec<String>> {
    Ok(source.split(split_by).map(|s| s.to_string()).collect())
}

// convert a string to a Rust file path
pub fn push_file_path(path: &str, suffix: &str) -> std::io::Result<std::path::PathBuf> {
    let mut p = path.to_owned();
    p.push_str(suffix);
    let r = std::path::Path::new(&p);
    Ok(r.to_owned())
}