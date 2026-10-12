//! pam_succeed_if — conditional rule evaluation (e.g. uid >= 1000, user = root).

use alloc::string::String;

use crate::constants::{PAM_AUTH_ERR, PAM_SUCCESS};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn eval_condition(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    if args.len() < 3 {
        return PamStatus::new(PAM_SUCCESS);
    }

    let username = match pamh.user() {
        Some(u) => u.to_string(),
        None => return PamStatus::new(PAM_AUTH_ERR),
    };

    let field = &args[0];
    let op = &args[1];
    let expected = &args[2];

    let pw = crate::modutil::passwd_by_name(&username);

    let field_val = match field.as_str() {
        "user" => username.clone(),
        "uid" => match &pw {
            Some(pw) => pw.uid.to_string(),
            None => return PamStatus::new(PAM_AUTH_ERR),
        },
        "gid" => match &pw {
            Some(pw) => pw.gid.to_string(),
            None => return PamStatus::new(PAM_AUTH_ERR),
        },
        _ => return PamStatus::new(PAM_SUCCESS),
    };

    let matched = match op.as_str() {
        "=" | "==" => field_val == *expected,
        "!=" => field_val != *expected,
        ">=" => field_val.parse::<u32>().unwrap_or(0) >= expected.parse::<u32>().unwrap_or(0),
        "<=" => field_val.parse::<u32>().unwrap_or(0) <= expected.parse::<u32>().unwrap_or(0),
        ">" => field_val.parse::<u32>().unwrap_or(0) > expected.parse::<u32>().unwrap_or(0),
        "<" => field_val.parse::<u32>().unwrap_or(0) < expected.parse::<u32>().unwrap_or(0),
        _ => true,
    };

    if matched {
        PamStatus::new(PAM_SUCCESS)
    } else {
        PamStatus::new(PAM_AUTH_ERR)
    }
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("succeed_if"),
        authenticate: Some(eval_condition),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(eval_condition),
        open_session: Some(eval_condition),
        close_session: Some(eval_condition),
        chauthtok: Some(eval_condition),
    }
}
