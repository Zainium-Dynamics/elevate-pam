//! pam_localuser — check if user exists in local /etc/passwd.

use alloc::string::String;

use crate::constants::{PAM_SUCCESS, PAM_USER_UNKNOWN};
use crate::error::PamStatus;
use crate::handle::PamHandle;
use crate::module::{ModuleHooks, ModuleId};

fn check_local(pamh: &mut PamHandle, _flags: i32, _args: &[String]) -> PamStatus {
    let username = match pamh.user() {
        Some(u) => u,
        None => return PamStatus::new(PAM_USER_UNKNOWN),
    };

    if crate::modutil::passwd_by_name(&username).is_some() {
        PamStatus::new(PAM_SUCCESS)
    } else {
        PamStatus::new(PAM_USER_UNKNOWN)
    }
}

pub fn hooks() -> ModuleHooks {
    ModuleHooks {
        id: ModuleId::normalize("localuser"),
        authenticate: Some(check_local),
        setcred: Some(|_, _, _| PamStatus::new(PAM_SUCCESS)),
        acct_mgmt: Some(check_local),
        open_session: None,
        close_session: None,
        chauthtok: None,
    }
}
