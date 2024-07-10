use tfhe::integer::{IntegerCiphertext, RadixCiphertext};
use tfhe::{integer, shortint};
use tfhe::shortint::MessageModulus;
use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

fn main() {
  //Generate compatible shortint and integer keys
  let short_ck = shortint::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
  let ck = integer::ClientKey::from_raw_parts(short_ck.clone());
  let short_sk = shortint::ServerKey::new(&short_ck);
  let sk = integer::ServerKey::new_radix_server_key_from_shortint(short_sk.clone());
  
  //Create luts for individual digits
  let v1 = [0u64,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3];
  let lut1 = short_sk.generate_lookup_table(|i| v1[i as usize]);
  let v2 = [1u64,2,3,0,1,2,3,0,1,2,3,0,1,2,3,0];
  let lut2 = short_sk.generate_lookup_table(|i| v2[i as usize]);
  let v3 = [2u64,3,0,1,2,3,0,1,2,3,0,1,2,3,0,1];
  let lut3 = short_sk.generate_lookup_table(|i| v3[i as usize]);
  let v4 = [3u64,0,1,2,3,0,1,2,3,0,1,2,3,0,1,2];
  let lut4 = short_sk.generate_lookup_table(|i| v4[i as usize]);
  
  let mut values: Vec<RadixCiphertext> = Vec::with_capacity(16);
  let mut clear_res = 0;
  
  //For all indices
  //* apply lookup with same index on all luts
  //* Aggregate results to RadixCiphertext
  //* Extend to 6 blocks
  //* Store to values
  for i in 0..16 {
      let ct = short_ck.encrypt_with_message_modulus(i, MessageModulus(16));
  
      let d1 = short_sk.apply_lookup_table(&ct, &lut1);
      let d2 = short_sk.apply_lookup_table(&ct, &lut2);
      let d3 = short_sk.apply_lookup_table(&ct, &lut3);
      let d4 = short_sk.apply_lookup_table(&ct, &lut4);
  
      let a1 = v1[i as usize];
      let a2 = v2[i as usize];
      let a3 = v3[i as usize];
      let a4 = v4[i as usize];
  
      assert_eq!([a1, a2, a3, a4], [
          short_ck.decrypt(&d1),
          short_ck.decrypt(&d2),
          short_ck.decrypt(&d3),
          short_ck.decrypt(&d4)
      ], "Decomposition digits differ");
  
      let mut value = RadixCiphertext::from_blocks(Vec::from([d1, d2, d3, d4]));
  
      let a = a1 + a2 * 4 + a3 * 16 + a4 * 64;
      clear_res += a;
  
      assert_eq!(a, ck.decrypt_radix::<u64>(&value), "Composed values differ");
  
      sk.extend_radix_with_trivial_zero_blocks_msb_assign(&mut value, 6);
  
      values.push(value);
  }
  
  // Perform sum over all values
  let sum: RadixCiphertext = sk.sum_ciphertexts_parallelized(&values).unwrap();
  
  assert_eq!(clear_res, ck.decrypt_radix::<u64>(&sum), "Total sum differs");
}
