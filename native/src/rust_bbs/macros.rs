macro_rules! handle_err {
  ($e:expr) => {
    return Err(BBSError::from(BBSErrorKind::GeneralError {
      msg: $e.to_string(),
    }));
  };
}
