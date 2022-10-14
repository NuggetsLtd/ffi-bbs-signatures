
macro_rules! arg_to_slice {
  ($cx:expr, $i:expr) => {{
      let arg: Handle<JsArrayBuffer> = $cx.argument::<JsArrayBuffer>($i)?;
      $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
  }};
}

macro_rules! handle_err {
  ($e:expr, $cx:expr) => {
      let err = json!({
        "error": {
          "name": "RustError",
          "message": $e
        }
      });

      match serde_json::to_string(&err) {
        Ok(err_string) => { return Ok($cx.string(err_string)) },
        Err(_) => { return Ok($cx.string("Unable to create string for error")) } 
      }
  };
}
