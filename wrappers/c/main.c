#include <stdio.h>
#include <string.h>
#include "libbbs.h"

typedef unsigned char BYTE;

void string2ByteArray(char* input, BYTE* output)
{
    int loop;
    int i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')
    {
        output[i++] = input[loop++];
    }
}

void generateBlindedG1Key(char* context)
{
  JsonString json_string;
  ByteArray contextBuffer;

  // populate blinding context buffer
  contextBuffer.length = strlen(context);
  BYTE contextBufferData[contextBuffer.length];
  string2ByteArray(context, contextBufferData);
  contextBuffer.data = contextBufferData;

  int outcome = bls_generate_blinded_g1_key(contextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nGenerated Blinded G1 Key:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nBlinded G1 Key Generation Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void generateBlindedG2Key(char* context)
{
  JsonString json_string;
  ByteArray contextBuffer;

  // populate blinding context buffer
  contextBuffer.length = strlen(context);
  BYTE contextBufferData[contextBuffer.length];
  string2ByteArray(context, contextBufferData);
  contextBuffer.data = contextBufferData;

  int outcome = bls_generate_blinded_g2_key(contextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nGenerated Blinded G2 Key:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nBlinded G2 Key Generation Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void generateG1Key(char* context)
{
  JsonString json_string;
  ByteArray contextBuffer;

  // populate blinding context buffer
  contextBuffer.length = strlen(context);
  BYTE contextBufferData[contextBuffer.length];
  string2ByteArray(context, contextBufferData);
  contextBuffer.data = contextBufferData;

  int outcome = bls_generate_g1_key(contextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nGenerated G1 Key:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nG1 Key Generation Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void generateG2Key(char* context)
{
  JsonString json_string;
  ByteArray contextBuffer;

  // populate blinding context buffer
  contextBuffer.length = strlen(context);
  BYTE contextBufferData[contextBuffer.length];
  string2ByteArray(context, contextBufferData);
  contextBuffer.data = contextBufferData;

  int outcome = bls_generate_g2_key(contextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nGenerated G2 Key:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nG2 Key Generation Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void blsSecretKeyToBbsPublicKey(char* context)
{
  JsonString json_string;
  ByteArray contextBuffer;

  // populate blinding context buffer
  contextBuffer.length = strlen(context);
  BYTE contextBufferData[contextBuffer.length];
  string2ByteArray(context, contextBufferData);
  contextBuffer.data = contextBufferData;

  int outcome = bls_secret_key_to_bbs_key(contextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nBLS Secret Key converted:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nBLS Secret Key conversion Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void blsPublicKeyToBbsPublicKey(char* context)
{
  JsonString json_string;
  ByteArray contextBuffer;

  // populate blinding context buffer
  contextBuffer.length = strlen(context);
  BYTE contextBufferData[contextBuffer.length];
  string2ByteArray(context, contextBufferData);
  contextBuffer.data = contextBufferData;

  int outcome = bls_public_key_to_bbs_key(contextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nBLS Public Key converted:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nBLS Public Key conversion Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void bbsSign(char* context)
{
  JsonString json_string;
  ByteArray contextBuffer;

  // populate blinding context buffer
  contextBuffer.length = strlen(context);
  BYTE contextBufferData[contextBuffer.length];
  string2ByteArray(context, contextBufferData);
  contextBuffer.data = contextBufferData;

  int outcome = bbs_sign(contextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nBBS Sign:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nBBS Sign Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void blindSignatureCommitment(char* blinding_context)
{
  JsonString json_string;
  ByteArray blindingContextBuffer;

  // populate blinding context buffer
  blindingContextBuffer.length = strlen(blinding_context);
  BYTE blindingContextBufferData[blindingContextBuffer.length];
  string2ByteArray(blinding_context, blindingContextBufferData);
  blindingContextBuffer.data = blindingContextBufferData;

  int outcome = bbs_blind_signature_commitment(blindingContextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nGenerated Blind Signature Commitment:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nBlind Signature Commitment Generation Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void verifyBlindSignatureCommitment(char* commitment_context)
{
  JsonString json_string;
  ByteArray commitmentContextBuffer;

  // populate blinding context buffer
  commitmentContextBuffer.length = strlen(commitment_context);
  BYTE commitmentContextBufferData[commitmentContextBuffer.length];
  string2ByteArray(commitment_context, commitmentContextBufferData);
  commitmentContextBuffer.data = commitmentContextBufferData;

  int outcome = bbs_verify_blind_signature_proof(commitmentContextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nBlind Signature Commitment verified:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nBlind Signature Commitment verification Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void blindSignMessages(char* blind_sign_context)
{
  JsonString json_string;
  ByteArray blindSignContextBuffer;

  // populate blind sign context buffer
  blindSignContextBuffer.length = strlen(blind_sign_context);
  BYTE blindSignContextBufferData[blindSignContextBuffer.length];
  string2ByteArray(blind_sign_context, blindSignContextBufferData);
  blindSignContextBuffer.data = blindSignContextBufferData;

  int outcome = bbs_blind_sign(blindSignContextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nBlind Sign:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nBlind Sign Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void unblindSignature(char* unblind_signature_context)
{
  JsonString json_string;
  ByteArray unblindSignatureContextBuffer;

  // populate blind sign context buffer
  unblindSignatureContextBuffer.length = strlen(unblind_signature_context);
  BYTE unblindSignatureContextBufferData[unblindSignatureContextBuffer.length];
  string2ByteArray(unblind_signature_context, unblindSignatureContextBufferData);
  unblindSignatureContextBuffer.data = unblindSignatureContextBufferData;

  int outcome = bbs_get_unblinded_signature(unblindSignatureContextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nUnblind Signature:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nUnblind Signature Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

void verifySignature(char* verify_signature_context)
{
  JsonString json_string;
  ByteArray verifySignatureContextBuffer;

  // populate blind sign context buffer
  verifySignatureContextBuffer.length = strlen(verify_signature_context);
  BYTE verifySignatureContextBufferData[verifySignatureContextBuffer.length];
  string2ByteArray(verify_signature_context, verifySignatureContextBufferData);
  verifySignatureContextBuffer.data = verifySignatureContextBufferData;

  int outcome = bbs_verify(verifySignatureContextBuffer, &json_string);

  if (outcome == 0)
  {
    printf("\nVerify Signature:\n%s\n\n", json_string.ptr);
  } else {
    printf("\nVerify Signature Error:\n%s\n\n", json_string.ptr);
  }

  ffi_bbs_signatures_free_json_string(json_string);
}

int main()
{
  char* context_empty = "";
  char* context_empty_obj = "{}";

  // ----- Generate Blinded G1 key ----------------------------------------------------------------
  
  char* context_withSeed = "{\"seed\":\"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=\"}";
  generateBlindedG1Key(context_empty);
  generateBlindedG1Key(context_empty_obj);
  generateBlindedG1Key(context_withSeed);


  // ----- Generate Blinded G2 key ----------------------------------------------------------------
  
  generateBlindedG2Key(context_empty);
  generateBlindedG2Key(context_empty_obj);
  generateBlindedG2Key(context_withSeed);


  // ----- Generate G1 key ------------------------------------------------------------------------
  
  generateG1Key(context_empty);
  generateG1Key(context_empty_obj);
  generateG1Key(context_withSeed);


  // ----- Generate G2 key ------------------------------------------------------------------------
  
  generateG2Key(context_empty);
  generateG2Key(context_empty_obj);
  generateG2Key(context_withSeed);


  // ----- BLS Secret Key to BBS Public Key -------------------------------------------------------

  char* context_withMsgCount = "{\"message_count\":3}";
  char* context_withSecretKey = "{\"message_count\":3,\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\"}";
  blsSecretKeyToBbsPublicKey(context_empty);
  blsSecretKeyToBbsPublicKey(context_empty_obj);
  blsSecretKeyToBbsPublicKey(context_withMsgCount);
  blsSecretKeyToBbsPublicKey(context_withSecretKey);


  // ----- BLS Public Key to BBS Public Key -------------------------------------------------------

  char* context_withPublicKey = "{\"message_count\":3,\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36\"}";
  blsPublicKeyToBbsPublicKey(context_empty);
  blsPublicKeyToBbsPublicKey(context_empty_obj);
  blsPublicKeyToBbsPublicKey(context_withMsgCount);
  blsPublicKeyToBbsPublicKey(context_withPublicKey);


  // ----- BBS Sign -------------------------------------------------------------------------------

  char* context_withSecretKeyOnly = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\"}";
  char* context_withKeysSet = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
  char* context_withMessagesSet = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\",\"bWVzc2FnZTM=\"]}";
  bbsSign(context_empty);
  bbsSign(context_empty_obj);
  bbsSign(context_withSecretKeyOnly);
  bbsSign(context_withKeysSet);
  bbsSign(context_withMessagesSet);


  // ----- BBS Verify Signature -------------------------------------------------------------------

  char* context_verifySignature = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"signature\":\"q4GNvjY8j6f52z6JvDosufjDID5crfLLmxRat7BKRvMUIbKlRIRVqerA8nfnVYfUBuRyhAm5a84zBSAWhUUz2pqicLmABrfWMlTziZN9zm5s8D8nBIox3GKgh/yqUe4JP9WisLyY6xvA0t60ABhhzg==\",\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\",\"bWVzc2FnZTM=\"]}";
  verifySignature(context_empty);
  verifySignature(context_empty_obj);
  verifySignature(context_verifySignature);


  // ----- Blind Signature Commitment -------------------------------------------------------------

  char* blinding_context = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"nonce\":\"EqamqgeL3rJR/NNSaG+0vIBUrJ4YibkNMmeXVjjrpPk=\",\"blinded\":[0,1],\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\"]}";
  blindSignatureCommitment(blinding_context);

  blindSignatureCommitment(context_empty);

  blindSignatureCommitment(context_empty_obj);

  char* blinding_context_missing_blinded = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
  blindSignatureCommitment(blinding_context_missing_blinded);

  char* blinding_context_missing_messages = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1]}";
  blindSignatureCommitment(blinding_context_missing_messages);

  char* blinding_context_missing_nonce = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1],\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\"]}";
  blindSignatureCommitment(blinding_context_missing_nonce);


  // ----- Verify Blind Signature Commitment ------------------------------------------------------
  
  char* commitment_context = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1],\"blinding_factor\":\"LOwrFYCZgVHuKp29PYrN7SXcki1ReqbsS7QKxHgGzZo=\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\",\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"proof_of_hidden_messages\":\"ufRyU8xKmO3d6Sz6j2497DqbBSaNhRCZz7N+WN5UeuOuKAGkrBgnCcHjGWmguVV3AAAAAxYqeDIHA16qGlSoWObxJ/+ud+STJEYU7q+QRZ8GdzTVYRcZ6bVQfJVA7SdKqRcELttuWiC2d2wNJKqBBZLDmURLl5XaK4eUt9pSzqoB/UUZ2yVoJV1O0hy4qDLxyIDzQA==\"}";
  verifyBlindSignatureCommitment(commitment_context);
  
  char* commitment_context_failure = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0],\"blinding_factor\":\"LOwrFYCZgVHuKp29PYrN7SXcki1ReqbsS7QKxHgGzZo=\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\",\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"proof_of_hidden_messages\":\"ufRyU8xKmO3d6Sz6j2497DqbBSaNhRCZz7N+WN5UeuOuKAGkrBgnCcHjGWmguVV3AAAAAxYqeDIHA16qGlSoWObxJ/+ud+STJEYU7q+QRZ8GdzTVYRcZ6bVQfJVA7SdKqRcELttuWiC2d2wNJKqBBZLDmURLl5XaK4eUt9pSzqoB/UUZ2yVoJV1O0hy4qDLxyIDzQA==\"}";
  verifyBlindSignatureCommitment(commitment_context_failure);

  char* commitment_context_empty = "";
  verifyBlindSignatureCommitment(commitment_context_empty);

  char* commitment_context_empty_obj = "{}";
  verifyBlindSignatureCommitment(commitment_context_empty_obj);

  char* commitment_context_missing_challenge_hash = "{\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\"}";
  verifyBlindSignatureCommitment(commitment_context_missing_challenge_hash);

  char* commitment_context_missing_public_key = "{\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\"}";
  verifyBlindSignatureCommitment(commitment_context_missing_public_key);

  char* commitment_context_missing_proof_of_hidden_messages = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\"}";
  verifyBlindSignatureCommitment(commitment_context_missing_proof_of_hidden_messages);

  char* commitment_context_missing_blinded = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\",\"challenge_hash\":\"LID+l56uoBdFPrfBf574L4m8ENoJc8FFACbGV8sFGYM=\",\"proof_of_hidden_messages\":\"ufRyU8xKmO3d6Sz6j2497DqbBSaNhRCZz7N+WN5UeuOuKAGkrBgnCcHjGWmguVV3AAAAAxYqeDIHA16qGlSoWObxJ/+ud+STJEYU7q+QRZ8GdzTVYRcZ6bVQfJVA7SdKqRcELttuWiC2d2wNJKqBBZLDmURLl5XaK4eUt9pSzqoB/UUZ2yVoJV1O0hy4qDLxyIDzQA==\"}";
  verifyBlindSignatureCommitment(commitment_context_missing_blinded);


  // ----- Blind Sign Messages --------------------------------------------------------------------

  char* blind_sign_context = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"known\":[2],\"messages\":[\"bWVzc2FnZTM=\"],\"commitment\":\"lZqvKXwcgNrPMdsezEa9jso6NrHFozSCOH5J0ISjZjV5+YBCHl0++odC/XYVKAV1\"}";
  blindSignMessages(blind_sign_context);

  char* blind_sign_context_empty = "";
  blindSignMessages(blind_sign_context_empty);

  char* blind_sign_context_empty_obj = "{}";
  blindSignMessages(blind_sign_context_empty_obj);

  char* blind_sign_context_missing_public_key = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\"}";
  blindSignMessages(blind_sign_context_missing_public_key);

  char* blind_sign_context_missing_known = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
  blindSignMessages(blind_sign_context_missing_known);

  char* blind_sign_context_missing_messages = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"known\":[2]}";
  blindSignMessages(blind_sign_context_missing_messages);

  char* blind_sign_context_missing_commitment = "{\"secret_key\":\"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=\",\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"known\":[2],\"messages\":[\"bWVzc2FnZTM=\"]}";
  blindSignMessages(blind_sign_context_missing_commitment);


  // ----- Unblind Signature ----------------------------------------------------------------------

  char* blind_signature_context = "{\"blind_signature\":\"qvNzrFrZRXWjx82CC16qUO3LhNJ75R+wjyMSwCiWgBSABOOqtNoZnMUdWUPzu9t8BNs86kNGH5yBXPyIVRB6yxgkKx1UjgFy6QIxwpe0YBBqOFik1G94L0FJPayHRYb4cQPTBUzDtL6j+DR4h5BxIg==\",\"blinding_factor\":\"LOwrFYCZgVHuKp29PYrN7SXcki1ReqbsS7QKxHgGzZo=\"}";
  unblindSignature(blind_signature_context);


  // ----- Verify Signature -----------------------------------------------------------------------

  char* verify_signature_context_empty = "";
  verifySignature(verify_signature_context_empty);

  char* verify_signature_context_empty_obj = "{}";
  verifySignature(verify_signature_context_empty_obj);

  char* verify_signature_context_missing_signature = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
  verifySignature(verify_signature_context_missing_signature);

  char* verify_signature_context_missing_messages = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"signature\":\"jO8qDBGQsK/Zl6rAx+aBuUe0c6hE/G2Apyp2N8CH2icZT6Nyq1F9e0lBaFUpRBiqY9NwiXinApEfu6G08ZzTjA9AsZW1G1y0EhEZ0pjrbLYq2kubBG8zzIJafdpAWVwpgDMypevMw48Ex59Z9MVFdA==\"}";
  verifySignature(verify_signature_context_missing_messages);

  char* verify_signature_context = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"signature\":\"qvNzrFrZRXWjx82CC16qUO3LhNJ75R+wjyMSwCiWgBSABOOqtNoZnMUdWUPzu9t8BNs86kNGH5yBXPyIVRB6yxgkKx1UjgFy6QIxwpe0YBAjNtxnK2t8OPw6A2G7LnzgQyLBL54//6vvrD89/5c+uw==\",\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\",\"bWVzc2FnZTM=\"]}";
  verifySignature(verify_signature_context);
}
