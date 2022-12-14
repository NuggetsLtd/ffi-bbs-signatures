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

export {
  generateBls12381G1KeyPair,
  generateBls12381G2KeyPair,
  generateBlindedBls12381G1KeyPair,
  generateBlindedBls12381G2KeyPair,
} from "./bls12381";
export { bls12381toBbs } from "./bls12381toBbs";
export {
  BBS_SIGNATURE_LENGTH,
  sign,
  blsSign,
  verify,
  blsVerify,
  createProof,
  blsCreateProof,
  verifyProof,
  blsVerifyProof,
  commitmentForBlindSignRequest,
  blsCommitmentForBlindSignRequest,
  verifyBlindSignContext,
  blsVerifyBlindSignContext,
  blindSign,
  blsBlindSign,
  unblindSignature,
} from "./bbsSignature";
export * from "./types";
