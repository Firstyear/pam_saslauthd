// #![deny(warnings)]

#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
// In this file, we do want to panic on these faults.
// #![deny(clippy::unwrap_used)]
// #![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

// extern crate libc;

mod pam;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::ffi::CStr;

use std::error::Error;
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime};

use crate::pam::constants::*;
use crate::pam::conv::PamConv;
use crate::pam::module::{PamHandle, PamHooks};

const SOCKET: &str = "/run/sasl2/mux";
const UNIX_SOCK_TIMEOUT: u64 = 8;

#[derive(Debug)]
struct ClientRequest {
    login_id: String,
    password: String,
    service: String,
    realm: String,
    client_addr: String,
}

impl ClientRequest {
    fn to_bytes(&self) -> Vec<u8> {
        // Send counts as u16 network order.
        let mut buf = Vec::with_capacity(
            self.login_id.len() +
            self.password.len() +
            self.service.len() +
            self.realm.len() +
            self.client_addr.len() +
            // Add 2 * 5 for the u16 counts.
            10,
        );

        buf.extend_from_slice(&(self.login_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.login_id.as_bytes());

        buf.extend_from_slice(&(self.password.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.password.as_bytes());

        buf.extend_from_slice(&(self.service.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.service.as_bytes());

        buf.extend_from_slice(&(self.realm.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.realm.as_bytes());

        buf.extend_from_slice(&(self.client_addr.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.client_addr.as_bytes());

        buf
    }
}

#[derive(Debug)]
struct ClientResponse {
    valid: bool,
}

impl TryFrom<Vec<u8>> for ClientResponse {
    type Error = Box<dyn Error>;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        // First two bytes is u16 in be order.
        if data.len() < 2 {
            return Err(Box::new(IoError::new(ErrorKind::Other, "Insufficent Data")));
        }

        let (left, right) = data.split_at(2);
        let count = u16::from_be_bytes(left.try_into().unwrap()) as usize;

        // Get the response.
        if right.len() < count {
            return Err(Box::new(IoError::new(ErrorKind::Other, "Insufficent Data")));
        }
        let (input, rem) = right.split_at(count);

        debug_assert!(rem.is_empty());

        let response = String::from_utf8(input.into())
            .map_err(|_| Box::new(IoError::new(ErrorKind::Other, "Invalid UTF8")))?;

        if response == "OK" {
            Ok(ClientResponse { valid: true })
        } else if response == "NO" {
            Ok(ClientResponse { valid: false })
        } else {
            Err(Box::new(IoError::new(ErrorKind::Other, "Invalid response")))
        }
    }
}

fn call_daemon_blocking(
    path: &str,
    req: &ClientRequest,
    timeout: u64,
    debug: bool,
) -> Result<ClientResponse, Box<dyn Error>> {
    let timeout = Duration::from_secs(timeout);

    let mut stream = UnixStream::connect(path)
        .and_then(|socket| socket.set_read_timeout(Some(timeout)).map(|_| socket))
        .and_then(|socket| socket.set_write_timeout(Some(timeout)).map(|_| socket))
        .map_err(|e| {
            if debug {
                println!("stream setup error -> {:?}", e);
            }
            e
        })
        .map_err(Box::new)?;

    let data = req.to_bytes();
    // Removed to not allow pw dump in production.
    // println!("data -> {:X?}", data);

    stream
        .write_all(data.as_slice())
        .and_then(|_| stream.flush())
        .map_err(|e| {
            if debug {
                println!("stream write error -> {:?}", e);
            }
            e
        })
        .map_err(Box::new)?;

    if debug {
        println!("request sent ...");
    }

    // Now wait on the response.
    let start = SystemTime::now();
    let mut read_started = false;
    let mut data = Vec::with_capacity(1024);
    let mut counter = 0;

    loop {
        let mut buffer = [0; 1024];
        let durr = SystemTime::now().duration_since(start).map_err(Box::new)?;
        if durr > timeout {
            if debug {
                println!("Socket timeout - {}", path);
            }
            // timed out, not enough activity.
            break;
        }
        // Would be a lot easier if we had peek ...
        // https://github.com/rust-lang/rust/issues/76923
        match stream.read(&mut buffer) {
            Ok(0) => {
                if read_started {
                    if debug {
                        println!("read_started true, we have completed");
                    }
                    // We're done, no more bytes.
                    break;
                } else {
                    if debug {
                        println!("Waiting ...");
                    }
                    // Still can wait ...
                    continue;
                }
            }
            Ok(count) => {
                data.extend_from_slice(&buffer);
                counter += count;
                if count == 1024 {
                    if debug {
                        println!("read 1024 bytes, looping ...");
                    }
                    // We have filled the buffer, we need to copy and loop again.
                    read_started = true;
                    continue;
                } else {
                    if debug {
                        println!("read {} bytes, complete", count);
                    }
                    // We have a partial read, so we are complete.
                    break;
                }
            }
            Err(e) => {
                if debug {
                    println!("Steam read failure -> {:?}", e);
                }
                // Failure!
                return Err(Box::new(e));
            }
        }
    }

    // Extend from slice fills with 0's, so we need to truncate now.
    data.truncate(counter);

    // Now attempt to decode.
    let cr = ClientResponse::try_from(data)?;

    Ok(cr)
}

#[derive(Debug)]
struct Options {
    debug: bool,
    use_first_pass: bool,
    // ignore_unknown_user: bool,
}

impl TryFrom<&Vec<&CStr>> for Options {
    type Error = ();

    fn try_from(args: &Vec<&CStr>) -> Result<Self, Self::Error> {
        let opts: Result<BTreeSet<&str>, _> = args.iter().map(|cs| cs.to_str()).collect();
        let gopts = match opts {
            Ok(o) => o,
            Err(e) => {
                println!("Error in module args -> {:?}", e);
                return Err(());
            }
        };

        Ok(Options {
            debug: gopts.contains("debug"),
            use_first_pass: gopts.contains("use_first_pass"),
            // ignore_unknown_user: gopts.contains("ignore_unknown_user"),
        })
    }
}

struct PamSaslauthd;
pam_hooks!(PamSaslauthd);

impl PamHooks for PamSaslauthd {
    fn acct_mgmt(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("acct_mgmt");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }

        PamResultCode::PAM_IGNORE
    }

    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_authenticate");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }
        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                println!("Error get_user -> {:?}", e);
                return e;
            }
        };

        let authtok = match pamh.get_authtok() {
            Ok(atok) => atok,
            Err(e) => {
                if opts.debug {
                    println!("Error get_authtok -> {:?}", e);
                }
                return e;
            }
        };

        let authtok = match authtok {
            Some(v) => v,
            None => {
                if opts.use_first_pass {
                    if opts.debug {
                        println!("Don't have an authtok, returning PAM_AUTH_ERR");
                    }
                    return PamResultCode::PAM_AUTH_ERR;
                } else {
                    let conv = match pamh.get_item::<PamConv>() {
                        Ok(conv) => conv,
                        Err(err) => {
                            if opts.debug {
                                println!("Couldn't get pam_conv");
                            }
                            return err;
                        }
                    };
                    match conv.send(PAM_PROMPT_ECHO_OFF, "Password: ") {
                        Ok(password) => match password {
                            Some(pw) => pw,
                            None => {
                                if opts.debug {
                                    println!("No password");
                                }
                                return PamResultCode::PAM_CRED_INSUFFICIENT;
                            }
                        },
                        Err(err) => {
                            if opts.debug {
                                println!("Couldn't get password");
                            }
                            return err;
                        }
                    }
                } // end opts.use_first_pass
            }
        };

        // Saslauthd has a very simple socket format per:
        // https://github.com/cyrusimap/cyrus-sasl/blob/master/saslauthd/ipc_unix.c#L328

        let (login_id, realm) = match account_id.split_once('@') {
            Some((lid, rlm)) => (lid.to_string(), rlm.to_string()),
            None => {
                // If there is no realm, leave it as a blank str.
                (account_id.to_string(), String::new())
            }
        };

        let req = ClientRequest {
            login_id,
            password: authtok,
            service: "pam_saslauthd".to_string(),
            realm,
            client_addr: "::1".to_string(),
        };

        match call_daemon_blocking(SOCKET, &req, UNIX_SOCK_TIMEOUT, opts.debug) {
            Ok(r) => {
                if r.valid {
                    PamResultCode::PAM_SUCCESS
                } else {
                    if opts.debug {
                        println!("PAM_AUTH_ERR - saslauthd rejected");
                    }
                    PamResultCode::PAM_AUTH_ERR
                }
            }
            Err(e) => {
                if opts.debug {
                    println!("PAM_IGNORE due to error -> {:?}", e);
                }
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_chauthtok(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_chauthtok");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }

        PamResultCode::PAM_IGNORE
    }

    fn sm_open_session(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_open_session");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }

        PamResultCode::PAM_SUCCESS
    }

    fn sm_close_session(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_close_session");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }

        PamResultCode::PAM_SUCCESS
    }

    fn sm_setcred(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_setcred");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }

        PamResultCode::PAM_SUCCESS
    }
}
