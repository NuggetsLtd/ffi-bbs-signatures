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

  }
}
