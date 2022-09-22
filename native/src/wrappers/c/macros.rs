macro_rules! handle_err {
    ($e:expr, $json_string:expr) => {
        // $e.map_err(|e| format!("{:?}", e)).unwrap()

        let err = json!({
          "error": {
            "name": "RustError",
            "message": $e
          }
        });
        match serde_json::to_string(&err) {
          Ok(mut blind_commitment_context_string) => {
            // add null terminator (for C-string)
            blind_commitment_context_string.push('\0');
      
            // box the string, so string isn't de-allocated on leaving the scope of this fn
            let boxed: Box<str> = blind_commitment_context_string.into_boxed_str();
          
            // set json_string pointer to boxed blind_commitment_context_string
            $json_string.ptr = Box::into_raw(boxed).cast();
          },
          Err(_) => ()
        }
        return 1;
    };
}
