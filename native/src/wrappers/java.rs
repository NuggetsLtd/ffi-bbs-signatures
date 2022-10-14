#[macro_use]
mod macros;

use crate::rust_bbs::{
  rust_bbs_blind_signature_size,
  rust_bbs_blinding_factor_size,
  rust_bls_public_key_g1_size,
  rust_bls_public_key_g2_size,
  rust_bls_secret_key_size,
  rust_bbs_signature_size,
  rust_bls_generate_blinded_g1_key,
  rust_bls_generate_blinded_g2_key,
  rust_bls_generate_g1_key,
  rust_bls_generate_g2_key,
  rust_bls_secret_key_to_bbs_key,
  rust_bls_public_key_to_bbs_key,
  rust_bbs_sign,
  rust_bbs_verify,
  rust_bbs_create_proof,
  rust_bbs_verify_proof,
  rust_bls_verify_proof,
  rust_bbs_blind_signature_commitment,
  rust_bbs_verify_blind_signature_proof,
  rust_bbs_blind_sign,
  rust_bbs_unblind_signature,
};
use serde_json::{Value, json};

// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::{JClass, JObject, JString};

// This is just a pointer. We'll be returning it from our function.
// We can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use jni::sys::{jstring, jbyteArray, jint};

use std::cell::RefCell;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_get_1last_1error<'a>(env: JNIEnv<'a>, _: JObject) -> JString<'a> {
    let mut res = env.new_string("").unwrap();
    LAST_ERROR.with(|prev| {
        match &*prev.borrow() {
            Some(s) => res = env.new_string(s).unwrap(),
            None => ()
        };
    });
    res
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bls_1public_1key_1g1_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
  rust_bls_public_key_g1_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bls_1public_1key_1g2_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
  rust_bls_public_key_g2_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_blinding_1factor_1size(_: JNIEnv, _: JObject) -> jint {
  rust_bbs_blinding_factor_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bls_1secret_1key_1size(_: JNIEnv, _: JObject) -> jint {
  rust_bls_secret_key_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bbs_1signature_1size(_: JNIEnv, _: JObject) -> jint {
  rust_bbs_signature_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_bbs_signatures_Bbs_bbs_1blind_1signature_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
  rust_bbs_blind_signature_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1generate_1blinded_1g1_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
      Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
      Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bls_generate_blinded_g1_key(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from blinded G1 key data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed to stringify Blinded G1 key: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1generate_1blinded_1g2_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bls_generate_blinded_g2_key(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from blinded G2 key data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed to stringify Blinded G2 key: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1generate_1g1_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bls_generate_g1_key(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from G1 key data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed to stringify G1 key: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1generate_1g2_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bls_generate_g2_key(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from G2 key data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed to stringify G2 key: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1secret_1key_1to_1bbs_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bls_secret_key_to_bbs_key(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from BBS key data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed to stringify BBS key: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1public_1key_1to_1bbs_1key(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bls_public_key_to_bbs_key(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from BBS key data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed to stringify BBS key: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1sign(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bbs_sign(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from BBS signature data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed to stringify BBS signature: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1create_1proof(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bbs_create_proof(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from BBS proof data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed generating proof of knowledge: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1verify_1proof(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bbs_verify_proof(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from BBS verification outcome");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed verifying proof of knowledge: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bls_1verify_1proof(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bls_verify_proof(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from BLS verification outcome");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed verifying proof of knowledge: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1blind_1signature_1commitment(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bbs_blind_signature_commitment(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from blind commitment data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed generating blind commitment: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1verify_1blind_1signature_1proof(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bbs_verify_blind_signature_proof(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from blind commitment verification data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed verifying blind commitment: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1blind_1sign(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bbs_blind_sign(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from blind signature data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed generating blind signature: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1get_1unblinded_1signature(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bbs_unblind_signature(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from unblind signature data");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed unblinding blinded signature: {:?}", error), env); }
  }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_life_nuggets_rs_Bbs_bbs_1verify(
  env: JNIEnv,
  _class: JClass,
  ctx: jbyteArray,
) -> jstring {
  let context_bytes;
  match env.convert_byte_array(ctx) {
    Err(_) => { handle_err!("Failed converting `ctx` to byte array", env); }
    Ok(bc) => context_bytes = bc,
  };

  // convert JSON string to JSON
  let context_json: Value = match String::from_utf8(context_bytes.to_vec()) {
    Ok(context_string) => {
      match serde_json::from_str(&context_string) {
        Ok(context) => context,
        Err(_) => { handle_err!("Failed parsing JSON context", env); }
      }
    },
    Err(_) => { handle_err!("Context not set", env); }
  };

  match rust_bbs_verify(context_json) {
    Ok(output_string) => {
      let output = env
        .new_string(output_string)
        .expect("Unable to create string from signature verification outcome");

      output.into_inner()
    }
    Err(error) => { handle_err!(format!("Failed verifying messages: {:?}", error), env); }
  }
}
