extern crate chrono;            // DateTime manipulation
extern crate arrayvec;

use chrono::offset::Utc;
use chrono::DateTime;

// get date into the format we need
pub fn format_date(time: DateTime<Utc>) -> Result<String, std::io::Error>  {
    Ok(time.format("%Y-%m-%d %H:%M:%S.%3f").to_string())
}

// convert string to i128 or return 0 if fails
pub fn to_int128(num: &str) -> i128 {
    let n = match num.parse::<i128>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

// convert string to i64 or return 0 if fails
pub fn to_int64(num: &str) -> i64 {
    let n = match num.parse::<i64>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

// convert string to i32 or return 0 if fails
pub fn to_int32(num: &str) -> i32 {
    let n = match num.parse::<i32>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

// convert string to i32 or return 0 if fails
/*
pub fn to_int16(num: &str) -> i16 {
    let n = match num.parse::<i16>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}
*/

// convert string to i8 or return 0 if fails
pub fn to_int8(num: &str) -> i8 {
    let n = match num.parse::<i8>() {
        Ok(i) => i,
        _ => 0
    };
    return n
}

/*
    Convert u128 to IPv6
        Procfs stores IPv6 as individual reversed dwords.
        Therefore have to break the 128bit value into 4 dwords, reverse them and recombine
    See: https://users.rust-lang.org/t/convert-hex-socket-notation-to-ip-and-port/33858/8
*/
pub fn u128_swap_u32s_then_to_ipv6 (n: u128) -> std::io::Result<::std::net::Ipv6Addr> {
    use ::arrayvec::ArrayVec;

    // Split u128 into four u32s
    let u32s: ArrayVec<[u32; 4]> =
            (0 .. 4)
            .rev()
            .map(|i| (n >> (32 * i)) as u32)
            .collect();
    
    // Convert each u32 into four u8s using network endianness
    let u8s: ArrayVec<[[u8; 4]; 4]> =
        u32s.into_iter()
            .map(u32::to_ne_bytes)
            .collect();
    
    // flatten the u8s
    let u8s: [u8; 16] = ArrayVec::into_inner(
        u8s.iter()
            .flat_map(|it| it.iter().copied())
            .collect()
        ).unwrap();

    // Convert the u8s into an Ipv6 address
    Ok(::std::net::Ipv6Addr::from(u8s))
}

// translate hex state to human readable
pub fn get_tcp_state(state: &str) -> String {
    match state {
        "01" => return "TCP_ESTABLISHED".to_string(),
        "02" => return "TCP_SYN_SENT".to_string(),
        "03" => return "TCP_SYN_RECV".to_string(),
        "04" => return "TCP_FIN_WAIT1".to_string(),
        "05" => return "TCP_FIN_WAIT2".to_string(),
        "06" => return "TCP_TIME_WAIT".to_string(),
        "07" => return "TCP_CLOSE".to_string(),
        "08" => return "TCP_CLOSE_WAIT".to_string(),
        "09" => return "TCP_LAST_ACK".to_string(),
        "0A" => return "TCP_LISTEN".to_string(),
        "0B" => return "TCP_CLOSING".to_string(),    /* Now a valid state */
        "0C" => return "TCP_MAX_STATES".to_string(),  /* Leave at the end! */
        _ => return "UNKNOWN".to_string()
    }
}

// split string on string and return vec
pub fn split_to_vec(source: &str, split_by: &str) -> Vec<String> {
    source.split(split_by).map(|s| s.to_string()).collect()
}

// convert a string to a Rust file path
pub fn push_file_path(path: &str, suffix: &str) -> std::path::PathBuf {
    let mut p = path.to_owned();
    p.push_str(suffix);
    let r = std::path::Path::new(&p);
    return r.to_owned()
}