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

int main()
{
  // ----- Blind Signature Commitment -------------------------------------------------------------
  char* blinding_context = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"nonce\":\"EqamqgeL3rJR/NNSaG+0vIBUrJ4YibkNMmeXVjjrpPk=\",\"blinded\":[0,1],\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\"]}";
  blindSignatureCommitment(blinding_context);

  char* blinding_context_empty = "";
  blindSignatureCommitment(blinding_context_empty);

  char* blinding_context_empty_obj = "{}";
  blindSignatureCommitment(blinding_context_empty_obj);

  char* blinding_context_missing_blinded = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\"}";
  blindSignatureCommitment(blinding_context_missing_blinded);

  char* blinding_context_missing_messages = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1]}";
  blindSignatureCommitment(blinding_context_missing_messages);

  char* blinding_context_missing_nonce = "{\"public_key\":\"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36rAn7qKBJ+zoJjiSDxFiBlgyjPKRQzw8R6VHRJ62cUPEBUxx8mk1FpuDBdeXA8NpgAAAAA5PIYj94+VZFiDLKmgZyHmxOlO7EotGWxuSh76d51g3LhfLgz/ZvY647AiDghQwuGY5WCek2c+ag44eKZnSs3qXUCzRZsKo+r2ax3iZoaVI0+y7U4v1T+ak6CNwiLEwTvrHv85q7BeuXiARgPPsjtGuOKpHguUYfRgPGnALw6UYWTwpqhwo2/uv5IRqjVgwEkA==\",\"blinded\":[0,1],\"messages\":[\"bWVzc2FnZTE=\",\"bWVzc2FnZTI=\"]}";
  blindSignatureCommitment(blinding_context_missing_nonce);
}