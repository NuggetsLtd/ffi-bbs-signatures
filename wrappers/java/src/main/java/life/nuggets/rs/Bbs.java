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

  private static native String bbs_blind_signature_commitment(byte[] blinding_context);

  private static native String bbs_verify_blind_signature_proof(byte[] commitment_context);


  // The rest is just regular ol' Java!
  public static void main(String[] args) {
    // ----- Generate Blind Signing Commitment ----------------------------------------------------

    System.out.println("\n***** Generate Blind Signing Commitment *****\n");
    
    System.out.println("\nSuccess:");
    String blindSigningCommitmentContext_missingNonce = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1],\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\"],\"nonce\":\"EqamqgeL3rJR/NNSaG+0vIBUrJ4YibkNMmeXVjjrpPk=\"}";
    System.out.println(Bbs.bbs_blind_signature_commitment(blindSigningCommitmentContext_missingNonce.getBytes()));
    
    System.out.println("\nEmpty context:");
    String blindSigningCommitmentContext_empty = "";
    System.out.println(Bbs.bbs_blind_signature_commitment(blindSigningCommitmentContext_empty.getBytes()));
    
    System.out.println("\nEmpty context obj:");
    String blindSigningCommitmentContext_emptyObj = "{}";
    System.out.println(Bbs.bbs_blind_signature_commitment(blindSigningCommitmentContext_emptyObj.getBytes()));
    
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
    String commitmentContext_empty = "";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext_empty.getBytes()));
    
    System.out.println("\nEmpty context obj:");
    String commitmentContext_emptyObj = "{}";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext_emptyObj.getBytes()));
    
    System.out.println("\nMissing 'challenge_hash' property:");
    String commitmentContext_missingCommitment = "{\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\"}";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext_missingCommitment.getBytes()));
    
    System.out.println("\nMissing 'public_key' property:");
    String commitmentContext_missingPublicKey = "{\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\"}";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext_missingPublicKey.getBytes()));
    
    System.out.println("\nMissing 'proof_of_hidden_messages' property:");
    String commitmentContext_missingProofOfHidden = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\"}";
    System.out.println(Bbs.bbs_verify_blind_signature_proof(commitmentContext_missingProofOfHidden.getBytes()));

  }
}
