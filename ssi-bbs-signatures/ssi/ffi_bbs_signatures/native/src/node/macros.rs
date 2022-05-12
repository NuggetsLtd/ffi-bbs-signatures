/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 macro_rules! slice_to_js_array_buffer {
  ($slice:expr, $cx:expr) => {{
      let mut result = JsArrayBuffer::new(&mut $cx, $slice.len() as u32)?;
      $cx.borrow_mut(&mut result, |d| {
          let bytes = d.as_mut_slice::<u8>();
          bytes.copy_from_slice($slice);
      });
      result
  }};
}

macro_rules! arg_to_slice {
  ($cx:expr, $i:expr) => {{
      let arg: Handle<JsArrayBuffer> = $cx.argument::<JsArrayBuffer>($i)?;
      $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
  }};
}

macro_rules! arg_to_opt_slice {
  ($cx:expr, $i:expr) => {{
    match $cx.argument_opt($i) {
        Some(_) => Some(arg_to_slice!($cx, $i)),
        None => None
    }
  }};
}

macro_rules! obj_property_to_slice {
  ($cx:expr, $obj:expr, $field:expr) => {{
      let arg: Handle<JsArrayBuffer> = $obj.get::<JsArrayBuffer, _, _>($cx, $field)?;
      $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
  }};
}

macro_rules! obj_property_to_opt_slice {
    ($cx:expr, $obj:expr, $field:expr) => {{
        match $obj.get::<JsArrayBuffer, _, _>($cx, $field) {
          Ok(_) => Some(obj_property_to_slice!($cx, $obj, $field)),
          Err(_) => None,
        }
    }};
}

macro_rules! obj_property_to_unsigned_int {
  ($cx:expr, $obj:expr, $field:expr) => {{
      let property_value: Handle<JsNumber> = $obj.get($cx, $field)?;
      let property_value: f64 = property_value.value();
      let zero: f64 = 0 as f64;

      if property_value < zero {
          panic!("{} cannot be negative: {}", $field, property_value);
      }

      property_value as u32
  }};
}

macro_rules! cast_to_number {
  ($cx:expr, $val:expr) => {{
      $val.downcast::<JsNumber>().unwrap_or($cx.number(-1)).value()
  }};
}

macro_rules! obj_property_to_vec {
    ($cx:expr, $obj:expr, $field:expr) => {{
        let arr: Handle<JsArray> = $obj.get($cx, $field)?;
        arr.to_vec($cx).expect("no messages")
    }};
}

macro_rules! blinded_key_values_to_object {
  ($cx:expr, $sk:expr, $pk:expr, $bf:expr) => {{
      let result = key_values_to_object!($cx, $sk, $pk);

      let bf_array  = slice_to_js_array_buffer!(&$bf[..], $cx);
      result.set(&mut $cx, "blindingFactor", bf_array)?;
    
      result
  }};
}

macro_rules! key_values_to_object {
  ($cx:expr, $sk:expr, $pk:expr) => {{
      let result = JsObject::new(&mut $cx);
    
      let pk_array = slice_to_js_array_buffer!(&$pk[..], $cx);
      result.set(&mut $cx, "publicKey", pk_array)?;
    
      let sk_array = slice_to_js_array_buffer!(&$sk[..], $cx);
      result.set(&mut $cx, "secretKey", sk_array)?;
    
      result
  }};
}

macro_rules! js_array_buffer_to_slice {
  ($cx:expr, $obj:expr) => {{
      let arg = $obj.downcast::<JsArrayBuffer>().or_throw($cx)?;
      $cx.borrow(&arg, |d| d.as_slice::<u8>()).to_vec()
  }};
}

macro_rules! obj_property_to_fixed_array {
  ($cx:expr, $obj:expr, $field:expr, $start:expr, $end:expr) => {{
      let a = obj_property_to_slice!($cx, $obj, $field);
      if a.len() != $end {
          panic!("Invalid length");
      }
      *array_ref![a, $start, $end]
  }};
}

macro_rules! arg_to_fixed_array {
    ($cx:expr, $i:expr, $start:expr, $end:expr) => {{
        let a = arg_to_slice!($cx, $i);
        if a.len() != $end {
            panic!("Invalid length");
        }
        *array_ref![a, $start, $end]
    }};
}

macro_rules! handle_err {
    ($e:expr) => {
        $e.map_err(|e| format!("{:?}", e)).unwrap()
    };
}
