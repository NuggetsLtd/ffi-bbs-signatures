package life.nuggets.rs;

/*
 * Wraps -lbbs native layer with an idiomatic Java layer
 *
 * To generate the JNI template for rust, run * `javac -h . Bbs.java`
 * used by the src/android.rs
 */

public class Bbs {
  
  static {
      // This actually loads the shared object that we'll be creating.
      // The actual location of the .so or .dll may differ based on your
      // platform.
      System.loadLibrary("bbs");
  }

  private static native String bls_generate_blinded_g1_key(byte[] context);
  private static native String bls_generate_blinded_g2_key(byte[] context);
  private static native String bls_generate_g1_key(byte[] context);
  private static native String bls_generate_g2_key(byte[] context);
  private static native String bls_secret_key_to_bbs_key(byte[] context);
  private static native String bls_public_key_to_bbs_key(byte[] context);
  private static native String bbs_sign(byte[] context);
  private static native String bls_sign(byte[] context);
  private static native String bbs_create_proof(byte[] context);
  private static native String bls_create_proof(byte[] context);
  private static native String bbs_verify_proof(byte[] context);
  private static native String bls_verify_proof(byte[] context);
  private static native String bbs_blind_signature_commitment(byte[] context);
  private static native String bls_blind_signature_commitment(byte[] context);
  private static native String bbs_verify_blind_signature_proof(byte[] context);
  private static native String bls_verify_blind_signature_proof(byte[] context);
  private static native String bbs_blind_sign(byte[] context);
  private static native String bls_blind_sign(byte[] context);
  private static native String bbs_get_unblinded_signature(byte[] context);
  private static native String bbs_verify(byte[] context);
  private static native String bls_verify(byte[] context);

  public static void main(String[] args) {

    String context_empty = "";
    String context_emptyObj = "{}";


    // ----- Generate Blinded G1 key --------------------------------------------------------------

    System.out.println("\n***** Generate Blinded G1 key *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bls_generate_blinded_g1_key(context_empty.getBytes()));
    
    System.out.println("\nSeed NOT set:");
    System.out.println(Bbs.bls_generate_blinded_g1_key(context_emptyObj.getBytes()));
    
    System.out.println("\nSeed SET:");
    String context_withSeed = "{\"seed\":\"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=\"}";
    System.out.println(Bbs.bls_generate_blinded_g1_key(context_withSeed.getBytes()));


    // ----- Generate Blinded G2 key --------------------------------------------------------------

    System.out.println("\n\n***** Generate Blinded G2 key *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bls_generate_blinded_g2_key(context_empty.getBytes()));
    
    System.out.println("\nSeed NOT set:");
    System.out.println(Bbs.bls_generate_blinded_g2_key(context_emptyObj.getBytes()));
    
    System.out.println("\nSeed SET:");
    System.out.println(Bbs.bls_generate_blinded_g2_key(context_withSeed.getBytes()));


    // ----- Generate G1 key ----------------------------------------------------------------------

    System.out.println("\n\n***** Generate G1 key *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bls_generate_g1_key(context_empty.getBytes()));
    
    System.out.println("\nSeed NOT set:");
    System.out.println(Bbs.bls_generate_g1_key(context_emptyObj.getBytes()));
    
    System.out.println("\nSeed SET:");
    System.out.println(Bbs.bls_generate_g1_key(context_withSeed.getBytes()));


    // ----- Generate G2 key ----------------------------------------------------------------------

    System.out.println("\n\n***** Generate G2 key *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bls_generate_g2_key(context_empty.getBytes()));
    
    System.out.println("\nSeed NOT set:");
    System.out.println(Bbs.bls_generate_g2_key(context_emptyObj.getBytes()));
    
    System.out.println("\nSeed SET:");
    System.out.println(Bbs.bls_generate_g2_key(context_withSeed.getBytes()));


    // ----- BLS Secret Key to BBS Public Key -----------------------------------------------------

    System.out.println("\n\n***** BLS Secret Key to BBS Public Key *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bls_secret_key_to_bbs_key(context_empty.getBytes()));
    
    System.out.println("\nMessage count NOT set:");
    System.out.println(Bbs.bls_secret_key_to_bbs_key(context_emptyObj.getBytes()));
    
    System.out.println("\nMessage count SET:");
    String context_withMessageCount = "{\"message_count\":3}";
    System.out.println(Bbs.bls_secret_key_to_bbs_key(context_withMessageCount.getBytes()));
    
    System.out.println("\nSecret key SET:");
    String context_withSecretKey = "{\"message_count\":3,\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\"}";
    System.out.println(Bbs.bls_secret_key_to_bbs_key(context_withSecretKey.getBytes()));


    // ----- BLS Public Key to BBS Public Key -----------------------------------------------------

    System.out.println("\n\n***** BLS Public Key to BBS Public Key *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bls_public_key_to_bbs_key(context_empty.getBytes()));
    
    System.out.println("\nMessage count NOT set:");
    System.out.println(Bbs.bls_public_key_to_bbs_key(context_emptyObj.getBytes()));
    
    System.out.println("\nMessage count SET:");
    System.out.println(Bbs.bls_public_key_to_bbs_key(context_withMessageCount.getBytes()));
    
    System.out.println("\nPublic key SET:");
    String context_withPublicKey = "{\"message_count\":3,\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36\"}";
    System.out.println(Bbs.bls_public_key_to_bbs_key(context_withPublicKey.getBytes()));


    // ----- BBS Sign -----------------------------------------------------------------------------

    System.out.println("\n\n***** BBS Sign *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bbs_sign(context_empty.getBytes()));
    
    System.out.println("\nSecret key NOT set:");
    System.out.println(Bbs.bbs_sign(context_emptyObj.getBytes()));
    
    System.out.println("\nSecret key SET:");
    String context_withSecretKeyOnly = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\"}";
    System.out.println(Bbs.bbs_sign(context_withSecretKeyOnly.getBytes()));
    
    System.out.println("\nPublic key SET:");
    String context_withKeysSet = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
    System.out.println(Bbs.bbs_sign(context_withKeysSet.getBytes()));
    
    System.out.println("\nMessages SET:");
    String context_withMessagesSet = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\",\"bWVzc2FnZTM=\"]}";
    System.out.println(Bbs.bbs_sign(context_withMessagesSet.getBytes()));
    

    // ----- BBS Verify Signature -----------------------------------------------------------------

    System.out.println("\n\n***** BBS Verify Signature *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bbs_verify(context_empty.getBytes()));
    
    System.out.println("\nPublic key NOT set:");
    System.out.println(Bbs.bbs_verify(context_emptyObj.getBytes()));
    
    System.out.println("\nSignature NOT set:");
    String context_withBbsPublicKey = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
    System.out.println(Bbs.bbs_verify(context_withBbsPublicKey.getBytes()));
    
    System.out.println("\nMessages NOT set:");
    String context_withBbsSignature = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"signature\":\"q4GNvjY8j6f52z6JvDosufjDID5crfLLmxRat7BKRvMUIbKlRIRVqerA8nfnVYfUBuRyhAm5a84zBSAWhUUz2pqicLmABrfWMlTziZN9zm5s8D8nBIox3GKgh/yqUe4JP9WisLyY6xvA0t60ABhhzg==\"}";
    System.out.println(Bbs.bbs_verify(context_withBbsSignature.getBytes()));

    System.out.println("\nVerify Signature:");
    String verifySignatureContext = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"signature\":\"q4GNvjY8j6f52z6JvDosufjDID5crfLLmxRat7BKRvMUIbKlRIRVqerA8nfnVYfUBuRyhAm5a84zBSAWhUUz2pqicLmABrfWMlTziZN9zm5s8D8nBIox3GKgh/yqUe4JP9WisLyY6xvA0t60ABhhzg==\",\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\",\"bWVzc2FnZTM=\"]}";
    System.out.println(Bbs.bbs_verify(verifySignatureContext.getBytes()));
    

    // ----- BBS Proof Derivation -----------------------------------------------------------------

    System.out.println("\n\n***** BBS Proof Derivation *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bbs_create_proof(context_empty.getBytes()));
    
    System.out.println("\nSignature NOT set:");
    System.out.println(Bbs.bbs_create_proof(context_emptyObj.getBytes()));
    
    System.out.println("\nPublic key NOT set:");
    String context_withBbsSignatureCreate = "{\"signature\":\"qg3PfohWGvbOCZWxcWIZ779aOuNSafjCXLdDux01TTNGm/Uqhr/kZZ1wSmxKwbEWAhctrDCp2mGE0M0l6DlA5R38chMbtnyWMfQgbQpzMQZgPBPUvVWivJyYEysZnQWrAYzZzRPe36VFbFy5ynWx0w==\"}";
    System.out.println(Bbs.bbs_create_proof(context_withBbsSignatureCreate.getBytes()));
    
    System.out.println("\nMessages NOT set:");
    String context_withBbsPublicKeyCreate = "{\"signature\":\"qg3PfohWGvbOCZWxcWIZ779aOuNSafjCXLdDux01TTNGm/Uqhr/kZZ1wSmxKwbEWAhctrDCp2mGE0M0l6DlA5R38chMbtnyWMfQgbQpzMQZgPBPUvVWivJyYEysZnQWrAYzZzRPe36VFbFy5ynWx0w==\",\"public_key\":\"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA==\"}";
    System.out.println(Bbs.bbs_create_proof(context_withBbsPublicKeyCreate.getBytes()));
    
    System.out.println("\nRevealed NOT set:");
    String context_withBbsMessagesCreate = "{\"signature\":\"qg3PfohWGvbOCZWxcWIZ779aOuNSafjCXLdDux01TTNGm/Uqhr/kZZ1wSmxKwbEWAhctrDCp2mGE0M0l6DlA5R38chMbtnyWMfQgbQpzMQZgPBPUvVWivJyYEysZnQWrAYzZzRPe36VFbFy5ynWx0w==\",\"public_key\":\"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA==\",\"messages\":[\"J42AxhciOVkE9w==\", \"PNMnARWIHP+s2g==\", \"ti9WYhhEej85jw==\"]}";
    System.out.println(Bbs.bbs_create_proof(context_withBbsMessagesCreate.getBytes()));
    
    System.out.println("\nProof Created:");
    String context_withBbsRevealedCreate = "{\"signature\":\"iVdrhH0s7PJySlsq6kmUtfs0mL0iKZ2MTT5kEBfQYyXl5316qejec3kCQlglVJPHYyMiAceWeZqB98GjMNtoyYTdK/5CTEJje/u+z/rxN3UnXYcIbqT7nDHOKPCKDipoRhPBRC2gyflhwrLh9no/4A==\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\",\"bWVzc2FnZTM=\"],\"revealed\":[0]}";
    System.out.println(Bbs.bbs_create_proof(context_withBbsRevealedCreate.getBytes()));
    

    // ----- BBS Verify Proof ---------------------------------------------------------------------

    System.out.println("\n\n***** BBS Verify Proof *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bbs_verify_proof(context_empty.getBytes()));
    
    System.out.println("\nProof NOT set:");
    System.out.println(Bbs.bbs_verify_proof(context_emptyObj.getBytes()));
    
    System.out.println("\nMessages NOT set:");
    String context_withBbsProof = "{\"proof\":\"AAMBsnS+vmHqCc0sTonk1yJgG8Vs+VaJcPRnCAlqJ0TBjuM1qupucfx0M7UoZnvd3Ohxj0V4xahyCmsSVDkmw0zVf5pXIG1/2waqT9vwd1sQapCYXNtfliDLLISHTzaLyMHKj761JUAUXPX5Z71WeaUZ6xhihB8KCRue1eb4zfZQ1lJ4Vv5sok5HQ3vi/9ZfSUGLAAAAdJZEwGWM9IyeFYQIpCT52YEhyn1B0Ed1ido8EdxjHhX2XCCkokXo8h+UeGLB/CapyQAAAAIrNyOxriOwmLgoepuExRcgYG3tY32NdAOlPraYhBckUGIs1efKTOcN7ULqpkhQOnQwhPSy6WDAXQP+dUZ/Pl6Ei/0+OXNfW5Tw3InZcYAVZh6PWr3468o7BwX7no2Kh+7iCXzxq4sQw+MwT11qHlZpAAAABDEdH7/RjjL7y4NirjS9sULyHS8FbK/KprsjBKCBC7XBTI88HG0SALBQXhvOznlxS7CCnGg8X8Tl3dNgjeOYyv86K+TcQHUWoj7mh9+OBUYbCluIZwmTQeh1pbT6UhK5bCub7xA20n5fEoBmPQR0vKd+ZIlWv4t8wr+uiQYk/2Iz\"}";
    System.out.println(Bbs.bbs_verify_proof(context_withBbsProof.getBytes()));
    
    System.out.println("\nPublic key NOT set:");
    String context_withMessages = "{\"proof\":\"AAMBsnS+vmHqCc0sTonk1yJgG8Vs+VaJcPRnCAlqJ0TBjuM1qupucfx0M7UoZnvd3Ohxj0V4xahyCmsSVDkmw0zVf5pXIG1/2waqT9vwd1sQapCYXNtfliDLLISHTzaLyMHKj761JUAUXPX5Z71WeaUZ6xhihB8KCRue1eb4zfZQ1lJ4Vv5sok5HQ3vi/9ZfSUGLAAAAdJZEwGWM9IyeFYQIpCT52YEhyn1B0Ed1ido8EdxjHhX2XCCkokXo8h+UeGLB/CapyQAAAAIrNyOxriOwmLgoepuExRcgYG3tY32NdAOlPraYhBckUGIs1efKTOcN7ULqpkhQOnQwhPSy6WDAXQP+dUZ/Pl6Ei/0+OXNfW5Tw3InZcYAVZh6PWr3468o7BwX7no2Kh+7iCXzxq4sQw+MwT11qHlZpAAAABDEdH7/RjjL7y4NirjS9sULyHS8FbK/KprsjBKCBC7XBTI88HG0SALBQXhvOznlxS7CCnGg8X8Tl3dNgjeOYyv86K+TcQHUWoj7mh9+OBUYbCluIZwmTQeh1pbT6UhK5bCub7xA20n5fEoBmPQR0vKd+ZIlWv4t8wr+uiQYk/2Iz\",\"messages\":[\"bWVzc2FnZTE=\"]}";
    System.out.println(Bbs.bbs_verify_proof(context_withMessages.getBytes()));
    
    System.out.println("\nVerified (true):");
    String context_proofVerified = "{\"proof\":\"AAMBsnS+vmHqCc0sTonk1yJgG8Vs+VaJcPRnCAlqJ0TBjuM1qupucfx0M7UoZnvd3Ohxj0V4xahyCmsSVDkmw0zVf5pXIG1/2waqT9vwd1sQapCYXNtfliDLLISHTzaLyMHKj761JUAUXPX5Z71WeaUZ6xhihB8KCRue1eb4zfZQ1lJ4Vv5sok5HQ3vi/9ZfSUGLAAAAdJZEwGWM9IyeFYQIpCT52YEhyn1B0Ed1ido8EdxjHhX2XCCkokXo8h+UeGLB/CapyQAAAAIrNyOxriOwmLgoepuExRcgYG3tY32NdAOlPraYhBckUGIs1efKTOcN7ULqpkhQOnQwhPSy6WDAXQP+dUZ/Pl6Ei/0+OXNfW5Tw3InZcYAVZh6PWr3468o7BwX7no2Kh+7iCXzxq4sQw+MwT11qHlZpAAAABDEdH7/RjjL7y4NirjS9sULyHS8FbK/KprsjBKCBC7XBTI88HG0SALBQXhvOznlxS7CCnGg8X8Tl3dNgjeOYyv86K+TcQHUWoj7mh9+OBUYbCluIZwmTQeh1pbT6UhK5bCub7xA20n5fEoBmPQR0vKd+ZIlWv4t8wr+uiQYk/2Iz\",\"messages\":[\"bWVzc2FnZTE=\"],\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
    System.out.println(Bbs.bbs_verify_proof(context_proofVerified.getBytes()));
    
    System.out.println("\nVerified (false):");
    String context_proofInvalid = "{\"proof\":\"AAMBsnS+vmHqCc0sTonk1yJgG8Vs+VaJcPRnCAlqJ0TBjuM1qupucfx0M7UoZnvd3Ohxj0V4xahyCmsSVDkmw0zVf5pXIG1/2waqT9vwd1sQapCYXNtfliDLLISHTzaLyMHKj761JUAUXPX5Z71WeaUZ6xhihB8KCRue1eb4zfZQ1lJ4Vv5sok5HQ3vi/9ZfSUGLAAAAdJZEwGWM9IyeFYQIpCT52YEhyn1B0Ed1ido8EdxjHhX2XCCkokXo8h+UeGLB/CapyQAAAAIrNyOxriOwmLgoepuExRcgYG3tY32NdAOlPraYhBckUGIs1efKTOcN7ULqpkhQOnQwhPSy6WDAXQP+dUZ/Pl6Ei/0+OXNfW5Tw3InZcYAVZh6PWr3468o7BwX7no2Kh+7iCXzxq4sQw+MwT11qHlZpAAAABDEdH7/RjjL7y4NirjS9sULyHS8FbK/KprsjBKCBC7XBTI88HG0SALBQXhvOznlxS7CCnGg8X8Tl3dNgjeOYyv86K+TcQHUWoj7mh9+OBUYbCluIZwmTQeh1pbT6UhK5bCub7xA20n5fEoBmPQR0vKd+ZIlWv4t8wr+uiQYk/2Iz\",\"messages\":[\"bWVzc2FnZTI=\"],\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
    System.out.println(Bbs.bbs_verify_proof(context_proofInvalid.getBytes()));
    

    // ----- BLS Verify Proof ---------------------------------------------------------------------

    System.out.println("\n\n***** BlS Verify Proof *****\n");
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bls_verify_proof(context_empty.getBytes()));
    
    System.out.println("\nSignature NOT set:");
    System.out.println(Bbs.bls_verify_proof(context_emptyObj.getBytes()));
    
    System.out.println("\nMessages NOT set:");
    System.out.println(Bbs.bls_verify_proof(context_withBbsProof.getBytes()));
    
    System.out.println("\nPublic key NOT set:");
    System.out.println(Bbs.bls_verify_proof(context_withMessages.getBytes()));
    
    System.out.println("\nVerified (true):");
    String context_proofBlsVerified = "{\"proof\":\"AAMBsnS+vmHqCc0sTonk1yJgG8Vs+VaJcPRnCAlqJ0TBjuM1qupucfx0M7UoZnvd3Ohxj0V4xahyCmsSVDkmw0zVf5pXIG1/2waqT9vwd1sQapCYXNtfliDLLISHTzaLyMHKj761JUAUXPX5Z71WeaUZ6xhihB8KCRue1eb4zfZQ1lJ4Vv5sok5HQ3vi/9ZfSUGLAAAAdJZEwGWM9IyeFYQIpCT52YEhyn1B0Ed1ido8EdxjHhX2XCCkokXo8h+UeGLB/CapyQAAAAIrNyOxriOwmLgoepuExRcgYG3tY32NdAOlPraYhBckUGIs1efKTOcN7ULqpkhQOnQwhPSy6WDAXQP+dUZ/Pl6Ei/0+OXNfW5Tw3InZcYAVZh6PWr3468o7BwX7no2Kh+7iCXzxq4sQw+MwT11qHlZpAAAABDEdH7/RjjL7y4NirjS9sULyHS8FbK/KprsjBKCBC7XBTI88HG0SALBQXhvOznlxS7CCnGg8X8Tl3dNgjeOYyv86K+TcQHUWoj7mh9+OBUYbCluIZwmTQeh1pbT6UhK5bCub7xA20n5fEoBmPQR0vKd+ZIlWv4t8wr+uiQYk/2Iz\",\"messages\":[\"bWVzc2FnZTE=\"],\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36\"}";
    System.out.println(Bbs.bls_verify_proof(context_proofBlsVerified.getBytes()));
    
    System.out.println("\nVerified (false):");
    String context_proofBlsInvalid = "{\"proof\":\"AAMBsnS+vmHqCc0sTonk1yJgG8Vs+VaJcPRnCAlqJ0TBjuM1qupucfx0M7UoZnvd3Ohxj0V4xahyCmsSVDkmw0zVf5pXIG1/2waqT9vwd1sQapCYXNtfliDLLISHTzaLyMHKj761JUAUXPX5Z71WeaUZ6xhihB8KCRue1eb4zfZQ1lJ4Vv5sok5HQ3vi/9ZfSUGLAAAAdJZEwGWM9IyeFYQIpCT52YEhyn1B0Ed1ido8EdxjHhX2XCCkokXo8h+UeGLB/CapyQAAAAIrNyOxriOwmLgoepuExRcgYG3tY32NdAOlPraYhBckUGIs1efKTOcN7ULqpkhQOnQwhPSy6WDAXQP+dUZ/Pl6Ei/0+OXNfW5Tw3InZcYAVZh6PWr3468o7BwX7no2Kh+7iCXzxq4sQw+MwT11qHlZpAAAABDEdH7/RjjL7y4NirjS9sULyHS8FbK/KprsjBKCBC7XBTI88HG0SALBQXhvOznlxS7CCnGg8X8Tl3dNgjeOYyv86K+TcQHUWoj7mh9+OBUYbCluIZwmTQeh1pbT6UhK5bCub7xA20n5fEoBmPQR0vKd+ZIlWv4t8wr+uiQYk/2Iz\",\"messages\":[\"bWVzc2FnZTI=\"],\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36\"}";
    System.out.println(Bbs.bls_verify_proof(context_proofBlsInvalid.getBytes()));


    // ----- Generate Blind Signing Commitment ----------------------------------------------------

    System.out.println("\n\n***** Generate Blind Signing Commitment *****\n");
    
    System.out.println("\nSuccess:");
    String blindSigningCommitmentContext_missingNonce = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1],\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\"],\"nonce\":\"EqamqgeL3rJR/NNSaG+0vIBUrJ4YibkNMmeXVjjrpPk=\"}";
    System.out.println(Bbs.bbs_blind_signature_commitment(blindSigningCommitmentContext_missingNonce.getBytes()));
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bbs_blind_signature_commitment(context_empty.getBytes()));
    
    System.out.println("\nEmpty context obj:");
    System.out.println(Bbs.bbs_blind_signature_commitment(context_emptyObj.getBytes()));
    
    System.out.println("\nMissing 'blinded' property:");
    String blindSigningCommitmentContext_missingBlinded = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
    System.out.println(Bbs.bbs_blind_signature_commitment(blindSigningCommitmentContext_missingBlinded.getBytes()));
    
    System.out.println("\nMissing 'messages' property:");
    String blindSigningCommitmentContext_missingMessages = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1]}";
    System.out.println(Bbs.bbs_blind_signature_commitment(blindSigningCommitmentContext_missingMessages.getBytes()));


    // ----- Verify Blind Signing Commitment ----------------------------------------------------
    
    System.out.println("\n\n***** Verify Blind Signing Commitment *****\n");
    
    System.out.println("\nSuccess:");
    String commitmentContext = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1],\"blinding_factor\":\"LOwrFYCZgVHuKp29PYrN7SXcki1ReqbsS7QKxHgGzZo=\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\",\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"proof_of_hidden_messages\":\"ufRyU8xKmO3d6Sz6j2497DqbBSaNhRCZz7N+WN5UeuOuKAGkrBgnCcHjGWmguVV3AAAAAxYqeDIHA16qGlSoWObxJ/+ud+STJEYU7q+QRZ8GdzTVYRcZ6bVQfJVA7SdKqRcELttuWiC2d2wNJKqBBZLDmURLl5XaK4eUt9pSzqoB/UUZ2yVoJV1O0hy4qDLxyIDzQA==\"}";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext.getBytes()));
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bbs_verify_blind_signature_proof(context_empty.getBytes()));
    
    System.out.println("\nEmpty context obj:");
    System.out.println(Bbs.bbs_verify_blind_signature_proof(context_emptyObj.getBytes()));
    
    System.out.println("\nMissing 'challenge_hash' property:");
    String commitmentContext_missingCommitment = "{\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\"}";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext_missingCommitment.getBytes()));
    
    System.out.println("\nMissing 'public_key' property:");
    String commitmentContext_missingPublicKey = "{\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\"}";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext_missingPublicKey.getBytes()));
    
    System.out.println("\nMissing 'proof_of_hidden_messages' property:");
    String commitmentContext_missingProofOfHidden = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\"}";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext_missingProofOfHidden.getBytes()));


    // ----- Blind Sign ---------------------------------------------------------------------------
    
    System.out.println("\n\n***** Blind Sign Known Messages *****\n");
    
    System.out.println("\nSuccess:");
    String blindSignContext = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"known\":[2],\"messages\":[\"bWVzc2FnZTM=\"],\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\"}";
    System.out.println(Bbs.bbs_blind_sign(blindSignContext.getBytes()));
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bbs_blind_sign(context_empty.getBytes()));
    
    System.out.println("\nEmpty context obj:");
    System.out.println(Bbs.bbs_blind_sign(context_emptyObj.getBytes()));
    
    System.out.println("\nMissing 'public_key' property:");
    String blindSignContext_missingPublicKey = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\"}";
    System.out.println(Bbs.bbs_blind_sign(blindSignContext_missingPublicKey.getBytes()));
    
    System.out.println("\nMissing 'known' property:");
    String blindSignContext_missingKnown = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
    System.out.println(Bbs.bbs_blind_sign(blindSignContext_missingKnown.getBytes()));
    
    System.out.println("\nMissing 'messages' property:");
    String blindSignContext_missingMessages = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"known\":[2]}";
    System.out.println(Bbs.bbs_blind_sign(blindSignContext_missingMessages.getBytes()));
    
    System.out.println("\nMissing 'commitment' property:");
    String blindSignContext_missingCommitment = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"known\":[2],\"messages\":[\"bWVzc2FnZTM=\"]}";
    System.out.println(Bbs.bbs_blind_sign(blindSignContext_missingCommitment.getBytes()));


    // ----- Unblind Signature --------------------------------------------------------------------
    
    System.out.println("\n\n***** Unblind Signature *****\n");
    
    System.out.println("\nSuccess:");
    String unblindSignatureContext = "{\"blind_signature\":\"qvNzrFrZRXWjx82CC16qUO3LhNJ75R+wjyMSwCiWgBSABOOqtNoZnMUdWUPzu9t8BNs86kNGH5yBXPyIVRB6yxgkKx1UjgFy6QIxwpe0YBBqOFik1G94L0FJPayHRYb4cQPTBUzDtL6j+DR4h5BxIg==\",\"blinding_factor\":\"LOwrFYCZgVHuKp29PYrN7SXcki1ReqbsS7QKxHgGzZo=\"}";
    System.out.println(Bbs.bbs_get_unblinded_signature(unblindSignatureContext.getBytes()));
    
    System.out.println("\nEmpty context:");
    System.out.println(Bbs.bbs_get_unblinded_signature(context_empty.getBytes()));
    
    System.out.println("\nEmpty context obj:");
    System.out.println(Bbs.bbs_get_unblinded_signature(context_emptyObj.getBytes()));
    
    System.out.println("\nMissing 'blinding_factor' property:");
    String unblindSignatureContext_missingBlindingFactor = "{\"blind_signature\":\"qvNzrFrZRXWjx82CC16qUO3LhNJ75R+wjyMSwCiWgBSABOOqtNoZnMUdWUPzu9t8BNs86kNGH5yBXPyIVRB6yxgkKx1UjgFy6QIxwpe0YBBqOFik1G94L0FJPayHRYb4cQPTBUzDtL6j+DR4h5BxIg==\"}";
    System.out.println(Bbs.bbs_get_unblinded_signature(unblindSignatureContext_missingBlindingFactor.getBytes()));


    // ----- Verify Unblinded Signature -----------------------------------------------------------
    
    System.out.println("\n\n***** Verify Unblinded Signature *****\n");
    
    System.out.println("\nSuccess:");
    String verifyUnblindedSignatureContext = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"signature\":\"qvNzrFrZRXWjx82CC16qUO3LhNJ75R+wjyMSwCiWgBSABOOqtNoZnMUdWUPzu9t8BNs86kNGH5yBXPyIVRB6yxgkKx1UjgFy6QIxwpe0YBAjNtxnK2t8OPw6A2G7LnzgQyLBL54//6vvrD89/5c+uw==\",\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\",\"bWVzc2FnZTM=\"]}";
    System.out.println(Bbs.bbs_verify(verifyUnblindedSignatureContext.getBytes()));
    
    System.out.println("\n\n");
  }
}
