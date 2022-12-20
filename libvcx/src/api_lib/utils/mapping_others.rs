use std::sync::PoisonError;
use crate::api_lib::utils::libvcx_error::{LibvcxError, LibvcxErrorKind};

impl<T> From<PoisonError<T>> for LibvcxError {
    fn from(err: PoisonError<T>) -> Self {
        LibvcxError::from_msg(LibvcxErrorKind::PoisonedLock, err.to_string())
    }
}
