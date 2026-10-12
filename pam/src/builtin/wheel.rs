//! pam_wheel — require membership in group wheel (or configured group).

use alloc::string::String;

use crate::constants::{PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_SUCCESS, PAM_USER_UNKNOWN};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{arg_has, arg_value, ModuleHooks, ModuleId};

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("wheel"),
        authenticate: Some(check),
        setcred: None,
        acct_mgmt: Some(check),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}

fn check(pamh: &mut PamHandle, _flags: i32, args: &[String]) -> PamStatus {
    let user = match pamh.get_user(None) {
        Ok(u) => u,
        Err(e) => return e.to_status(),
    };
    let group = arg_value(args, "group").unwrap_or("wheel");
    let deny = arg_has(args, "deny");
    let root_only = arg_has(args, "root_only");

    if root_only {
        // only enforce when target is root — here we check requesting context
        // simplified: check if service implies elevate to root
    }

    let member = match is_group_member(&user, group) {
        Ok(m) => m,
        Err(_) => return PamStatus::new(PAM_USER_UNKNOWN),
    };

    if deny {
        if member {
            PamStatus::new(PAM_PERM_DENIED)
        } else {
            PamStatus::new(PAM_SUCCESS)
        }
    } else if member {
        PamStatus::new(PAM_SUCCESS)
    } else {
        PamStatus::new(PAM_AUTH_ERR)
    }
}

fn is_group_member(user: &str, group: &str) -> Result<bool, ()> {
    crate::modutil::user_in_group(user, group).ok_or(())
}
