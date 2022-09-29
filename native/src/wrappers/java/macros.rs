macro_rules! handle_err {
    ($e:expr, $env:expr) => {
        let err = json!({
          "error": {
            "name": "RustError",
            "message": $e
          }
        });
        let output;
        match serde_json::to_string(&err) {
          Ok(err_string) => {
            output = $env
                .new_string(err_string)
                .expect("Unable to create string for error");
          },
          Err(_) => {
            output = $env
              .new_string("An unknown error occurred")
              .expect("Unable to create string for error");
          }
        }
        return output.into_inner();
    };
}
