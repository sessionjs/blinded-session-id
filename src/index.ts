// Huge thanks to li0ard for this code
// CREDIT: https://github.com/theinfinityway/session_id/ [MIT]

import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { blake2b } from "@noble/hashes/blake2.js";
import {
	crypto_core_ed25519_scalar_reduce,
	crypto_sign_curve25519_pk_to_ed25519,
	crypto_scalarmult_ed25519_noclamp,
} from "./scalar-math";

function generateBlindingFactor(serverPk: Uint8Array) {
	const serverPkHash = blake2b(serverPk, {
		dkLen: 64,
	});
	return crypto_core_ed25519_scalar_reduce(serverPkHash);
}

export function generateKA(ed25519Pk: Uint8Array, serverPk: Uint8Array): Uint8Array {
	const kBytes = generateBlindingFactor(serverPk);
	const kA = crypto_scalarmult_ed25519_noclamp(kBytes, ed25519Pk);

	return kA;
}

export function generateBlindedKeys(ed25519Pk: Uint8Array, serverPk: Uint8Array): Uint8Array[] {
	const kA = generateKA(ed25519Pk, serverPk);
	const key1 = kA;

	const modifiedByte = kA[31] & 0x7f;
	const key2 = new Uint8Array(32);
	key2.set(kA.slice(0, 31), 0);
	key2[31] = modifiedByte;

	return [key1, key2];
}

export function blindSessionId({
	sessionId,
	sogsPublicKey,
}: {
	sessionId: string;
	sogsPublicKey: string;
}) {
	const x25519Pk = hexToBytes(sessionId.substring(2));
	const ed25519Pk = crypto_sign_curve25519_pk_to_ed25519(x25519Pk);
	const serverPk = hexToBytes(sogsPublicKey);
	const [key1, key2] = generateBlindedKeys(ed25519Pk, serverPk);

	// const isKey2 = key1[31] & 0x80;
	// if (isKey2) {
	// 	return ;
	// }

	return ["15" + bytesToHex(key1), "15" + bytesToHex(key2)];
}
