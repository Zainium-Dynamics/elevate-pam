//! unix_chkpwd — setuid-root helper, as Linux-PAM's: lets an unprivileged process (a screen
//! locker) check its own user's password or account expiry against the root-only shadow file.
//!
//!     unix_chkpwd <user> nullok|nonull     password on stdin, PAM code as exit status
//!     unix_chkpwd <user> chkexpiry         account/password expiry as exit status

use std::ffi::CString;
use std::io::{IsTerminal, Read};
use std::process::ExitCode;
use std::time::Duration;

use elevate_pam::constants::{
    PAM_AUTHINFO_UNAVAIL, PAM_AUTH_ERR, PAM_SUCCESS, PAM_SYSTEM_ERR, PAM_USER_UNKNOWN,
};

const MAX_PASSWORD: u64 = 1024;

/// The user's uid from the configured passwd file (libc's getpwnam only knows /etc/passwd).
fn uid_of(user: &str) -> Option<libc::uid_t> {
    let text = std::fs::read_to_string(elevate_pam::paths::get().passwd_file()).ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next() == Some(user)).then(|| f.nth(1)?.parse().ok())?
    })
}

fn log(msg: &str) {
    if let Ok(c) = CString::new(msg) {
        unsafe {
            libc::openlog(c"unix_chkpwd".as_ptr(), libc::LOG_PID, libc::LOG_AUTHPRIV);
            libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), c.as_ptr());
        }
    }
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(code as u8)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ruid = unsafe { libc::getuid() };

    // only pam_unix feeds this helper, through a pipe
    if std::io::stdin().is_terminal() || args.len() != 2 {
        log(&format!(
            "inappropriate use of Unix helper binary [UID={ruid}]"
        ));
        eprintln!("This binary is not designed for running in this way");
        std::thread::sleep(Duration::from_secs(10));
        return exit(PAM_SYSTEM_ERR);
    }
    let (user, option) = (&args[0], args[1].as_str());

    // a normal user may only ask about their own account
    if ruid != 0 && uid_of(user) != Some(ruid) {
        log(&format!("refused check of {user} for UID {ruid}"));
        return exit(PAM_AUTH_ERR);
    }

    let nullok = match option {
        "chkexpiry" => return exit(elevate_pam::builtin::account_status_code(user)),
        "nullok" => true,
        "nonull" => false,
        _ => return exit(PAM_SYSTEM_ERR),
    };

    let mut buf = Vec::new();
    if std::io::stdin()
        .take(MAX_PASSWORD)
        .read_to_end(&mut buf)
        .is_err()
    {
        return exit(PAM_SYSTEM_ERR);
    }
    while matches!(buf.last(), Some(b'\n' | b'\r' | b'\0')) {
        buf.pop();
    }
    let rc = match std::str::from_utf8(&buf) {
        Ok(plain) => elevate_pam::builtin::check_local_password(user, plain, nullok),
        Err(_) => PAM_AUTH_ERR,
    };
    let blank = buf.is_empty();
    buf.iter_mut().for_each(|b| *b = 0);

    if rc == PAM_SUCCESS {
        return exit(PAM_SUCCESS);
    }
    if !(nullok && blank) {
        log(&format!("password check failed for user ({user})"));
    }
    // the helper can be run directly, so it slows guessing itself
    std::thread::sleep(Duration::from_secs(1));
    exit(if rc == PAM_USER_UNKNOWN {
        PAM_AUTHINFO_UNAVAIL
    } else {
        PAM_AUTH_ERR
    })
}
