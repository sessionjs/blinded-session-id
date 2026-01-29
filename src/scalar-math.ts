// Credit: https://github.com/algorandfoundation/xHD-Wallet-API-ts/blob/2c5afbf6a1bed04ed952b65b754a36ed31669872/src/sumo.facade.ts
// License: Apache 2.0: https://github.com/algorandfoundation/xHD-Wallet-API-ts/blob/main/LICENSE

import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";

const crypto_scalarmult_ed25519_SCALARBYTES = 32;

export function crypto_scalarmult_ed25519_base_noclamp(scalar: Uint8Array): Uint8Array {
	if (scalar.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
		throw new Error(`scalar must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`);
	}

	const scalarBigint = bytesToNumberLE(scalar);

	try {
		const point = ed25519.Point.BASE.multiply(scalarBigint);
		return point.toBytes();
	} catch {
		if (scalarBigint === 0n) {
			const identity = new Uint8Array(32);
			identity[0] = 1;
			return identity;
		}

		const reducedScalar = mod(scalarBigint, ed25519.Point.Fn.ORDER);

		if (reducedScalar === 0n) {
			const identity = new Uint8Array(32);
			identity[0] = 1;
			return identity;
		}

		const point = ed25519.Point.BASE.multiply(reducedScalar);
		return point.toBytes();
	}
}

export function crypto_core_ed25519_scalar_add(
	scalarA: Uint8Array,
	scalarB: Uint8Array,
): Uint8Array {
	const a = bytesToNumberLE(scalarA);
	const b = bytesToNumberLE(scalarB);
	const result = mod(a + b, ed25519.Point.Fn.ORDER);

	return numberToBytesLE(result, 32);
}

export function crypto_core_ed25519_scalar_mul(
	scalarA: Uint8Array,
	scalarB: Uint8Array,
): Uint8Array {
	const a = bytesToNumberLE(scalarA);
	const b = bytesToNumberLE(scalarB);
	const result = mod(a * b, ed25519.Point.Fn.ORDER);

	return numberToBytesLE(result, 32);
}

export function crypto_core_ed25519_scalar_reduce(scalar: Uint8Array): Uint8Array {
	const scalarNum = bytesToNumberLE(scalar);
	const result = mod(scalarNum, ed25519.Point.Fn.ORDER);

	return numberToBytesLE(result, 32);
}

export function crypto_sign_ed25519_sk_to_curve25519(edPrivKey: Uint8Array): Uint8Array {
	const seed = edPrivKey.slice(0, 32);
	return ed25519.utils.toMontgomerySecret(seed);
}

export function crypto_sign_curve25519_pk_to_ed25519(x25519Pk: Uint8Array): Uint8Array {
	const P = 2n ** 255n - 19n;

	let u = 0n;
	for (let i = 0; i < x25519Pk.length; i++) {
		u += BigInt(x25519Pk[i]) << (8n * BigInt(i));
	}

	const modPow = (base: bigint, exp: bigint, mod: bigint): bigint => {
		let result = 1n;
		base = base % mod;
		while (exp > 0n) {
			if (exp % 2n === 1n) result = (result * base) % mod;
			exp = exp >> 1n;
			base = (base * base) % mod;
		}
		return result;
	};

	const modInv = (a: bigint): bigint => modPow(a, P - 2n, P);

	const y = (((u - 1n + P) % P) * modInv((u + 1n) % P)) % P;

	const yBytes = new Uint8Array(32);
	let yTemp = y;
	for (let i = 0; i < 32; i++) {
		yBytes[i] = Number(yTemp & 0xffn);
		yTemp >>= 8n;
	}

	yBytes[31] &= 0x7f;

	return yBytes;
}

export function crypto_scalarmult_ed25519_noclamp(
	scalar32: Uint8Array,
	point32: Uint8Array,
): Uint8Array {
	if (scalar32.length !== 32) {
		throw new Error(
			`crypto_scalarmult_ed25519_noclamp: expected 32-byte scalar, got ${scalar32.length}`,
		);
	}
	if (point32.length !== 32) {
		throw new Error(
			`crypto_scalarmult_ed25519_noclamp: expected 32-byte point, got ${point32.length}`,
		);
	}

	const L = ed25519.Point.Fn.ORDER;
	const s = bytesToNumberLE(scalar32) % L;

	const P = ed25519.Point.fromBytes(point32);
	if (P.isSmallOrder()) {
		throw new Error("crypto_scalarmult_ed25519_noclamp: invalid point (small order)");
	}

	return P.multiply(s).toBytes();
}
