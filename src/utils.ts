import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex } from "@noble/curves/utils.js";
import { crypto_core_ed25519_scalar_reduce } from "./scalar-math";

export const hexRegex = /^[0-9a-fA-F]+$/i;

export function getBlindingK(input: Uint8Array) {
	const serverPkHash = blake2b(input, {
		dkLen: 64,
	});
	const k = crypto_core_ed25519_scalar_reduce(serverPkHash);
	return k;
}

export function keyToSessionId(prefix: number, key: Uint8Array) {
	return bytesToHex(new Uint8Array([prefix, ...key]));
}
