// Credit: https://github.com/algorandfoundation/xHD-Wallet-API-ts/blob/2c5afbf6a1bed04ed952b65b754a36ed31669872/src/sumo.facade.ts
// License: Apache 2.0: https://github.com/algorandfoundation/xHD-Wallet-API-ts/blob/main/LICENSE

import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";

const crypto_scalarmult_ed25519_SCALARBYTES = 32;

export function crypto_scalarmult_ed25519_base_noclamp(scalar: Uint8Array): Uint8Array {
	// Input validation - only validate length
	if (scalar.length !== crypto_scalarmult_ed25519_SCALARBYTES) {
		throw new Error(`scalar must be ${crypto_scalarmult_ed25519_SCALARBYTES} bytes`);
	}

	// Convert scalar bytes to bigint (little-endian)
	const scalarBigint = bytesToNumberLE(scalar);

	try {
		// Try multiplication directly without any validation
		const point = ed25519.Point.BASE.multiply(scalarBigint);
		return point.toBytes();
	} catch {
		// Handle edge cases that libsodium noclamp supports but noble/curves rejects
		// This matches libsodium's noclamp behavior for invalid scalars

		// If scalar is 0, return identity point
		if (scalarBigint === 0n) {
			// Identity point in Ed25519: (0, 1) which compresses to 0x01 followed by zeros
			const identity = new Uint8Array(32);
			identity[0] = 1; // y-coordinate = 1, sign bit = 0
			return identity;
		}

		// For other edge cases (scalar >= curve order), reduce modulo curve order
		// This maintains compatibility with libsodium's noclamp behavior
		const reducedScalar = mod(scalarBigint, ed25519.Point.Fn.ORDER);

		// Handle reduced scalar of 0 after modular reduction
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
	// Convert little-endian bytes to bigint
	const a = bytesToNumberLE(scalarA);
	const b = bytesToNumberLE(scalarB);
	const result = mod(a + b, ed25519.Point.Fn.ORDER);

	// Convert back to little-endian bytes
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

// export function crypto_core_ed25519_scalar_reduce(scalar: Uint8Array): Uint8Array {
// 	const scalarNum = bytesToNumberLE(scalar);
// 	const result = mod(scalarNum, ed25519.Point.Fn.ORDER);

// 	return numberToBytesLE(result, 32);
// }

export function crypto_sign_ed25519_sk_to_curve25519(edPrivKey: Uint8Array): Uint8Array {
	// Extract just the seed (first 32 bytes) since edwardsToMontgomeryPriv expects 32 bytes
	const seed = edPrivKey.slice(0, 32);
	return ed25519.utils.toMontgomerySecret(seed);
}

// export function crypto_sign_curve25519_pk_to_ed25519(x25519Pk: Uint8Array): Uint8Array {
// 	const P = 2n ** 255n - 19n; // Curve25519 prime

// 	// Convert to bigint
// 	let u = 0n;
// 	for (let i = 0; i < x25519Pk.length; i++) {
// 		u += BigInt(x25519Pk[i]) << (8n * BigInt(i));
// 	}

// 	// Modular inverse (Fermat's little theorem: a^(-1) = a^(p-2) mod p)
// 	const modPow = (base: bigint, exp: bigint, mod: bigint): bigint => {
// 		let result = 1n;
// 		base = base % mod;
// 		while (exp > 0n) {
// 			if (exp % 2n === 1n) result = (result * base) % mod;
// 			exp = exp >> 1n;
// 			base = (base * base) % mod;
// 		}
// 		return result;
// 	};

// 	const modInv = (a: bigint): bigint => modPow(a, P - 2n, P);

// 	// y = (u - 1) / (u + 1) mod P
// 	const y = (((u - 1n + P) % P) * modInv((u + 1n) % P)) % P;

// 	// Convert to bytes (little-endian)
// 	const yBytes = new Uint8Array(32);
// 	let yTemp = y;
// 	for (let i = 0; i < 32; i++) {
// 		yBytes[i] = Number(yTemp & 0xffn);
// 		yTemp >>= 8n;
// 	}

// 	// Clear sign bit (use positive root)
// 	yBytes[31] &= 0x7f;

// 	return yBytes;
// }

export function ed25519ScalarmultNoClamp(scalar32: Uint8Array, point32: Uint8Array): Uint8Array {
	if (scalar32.length !== 32) {
		throw new Error(`ed25519ScalarmultNoClamp: expected 32-byte scalar, got ${scalar32.length}`);
	}
	if (point32.length !== 32) {
		throw new Error(`ed25519ScalarmultNoClamp: expected 32-byte point, got ${point32.length}`);
	}

	const L = ed25519.Point.Fn.ORDER;
	const s = bytesToNumberLE(scalar32) % L;

	const P = ed25519.Point.fromBytes(point32);
	if (P.isSmallOrder()) {
		throw new Error("ed25519ScalarmultNoClamp: invalid point (small order)");
	}

	return P.multiply(s).toBytes();
}

function gf(init?: number[]) {
	let i,
		r = new Float64Array(16);
	if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
	return r;
}

function unpack25519(o: Float64Array, n: Uint8Array) {
	let i;
	for (i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
	o[15] &= 0x7fff;
}

function A(o: Float64Array, a: Float64Array, b: Float64Array) {
	for (let i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

function Z(o: Float64Array, a: Float64Array, b: Float64Array) {
	for (let i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

function S(o: Float64Array, a: Float64Array) {
	M(o, a, a);
}

function inv25519(o: Float64Array, i: Float64Array) {
	const c = gf();
	let a;
	for (a = 0; a < 16; a++) c[a] = i[a];
	for (a = 253; a >= 0; a--) {
		S(c, c);
		if (a !== 2 && a !== 4) M(c, c, i);
	}
	for (a = 0; a < 16; a++) o[a] = c[a];
}

function M(o: Float64Array, a: Float64Array, b: Float64Array) {
	let v,
		c,
		t0 = 0,
		t1 = 0,
		t2 = 0,
		t3 = 0,
		t4 = 0,
		t5 = 0,
		t6 = 0,
		t7 = 0,
		t8 = 0,
		t9 = 0,
		t10 = 0,
		t11 = 0,
		t12 = 0,
		t13 = 0,
		t14 = 0,
		t15 = 0,
		t16 = 0,
		t17 = 0,
		t18 = 0,
		t19 = 0,
		t20 = 0,
		t21 = 0,
		t22 = 0,
		t23 = 0,
		t24 = 0,
		t25 = 0,
		t26 = 0,
		t27 = 0,
		t28 = 0,
		t29 = 0,
		t30 = 0,
		b0 = b[0],
		b1 = b[1],
		b2 = b[2],
		b3 = b[3],
		b4 = b[4],
		b5 = b[5],
		b6 = b[6],
		b7 = b[7],
		b8 = b[8],
		b9 = b[9],
		b10 = b[10],
		b11 = b[11],
		b12 = b[12],
		b13 = b[13],
		b14 = b[14],
		b15 = b[15];

	v = a[0];
	t0 += v * b0;
	t1 += v * b1;
	t2 += v * b2;
	t3 += v * b3;
	t4 += v * b4;
	t5 += v * b5;
	t6 += v * b6;
	t7 += v * b7;
	t8 += v * b8;
	t9 += v * b9;
	t10 += v * b10;
	t11 += v * b11;
	t12 += v * b12;
	t13 += v * b13;
	t14 += v * b14;
	t15 += v * b15;
	v = a[1];
	t1 += v * b0;
	t2 += v * b1;
	t3 += v * b2;
	t4 += v * b3;
	t5 += v * b4;
	t6 += v * b5;
	t7 += v * b6;
	t8 += v * b7;
	t9 += v * b8;
	t10 += v * b9;
	t11 += v * b10;
	t12 += v * b11;
	t13 += v * b12;
	t14 += v * b13;
	t15 += v * b14;
	t16 += v * b15;
	v = a[2];
	t2 += v * b0;
	t3 += v * b1;
	t4 += v * b2;
	t5 += v * b3;
	t6 += v * b4;
	t7 += v * b5;
	t8 += v * b6;
	t9 += v * b7;
	t10 += v * b8;
	t11 += v * b9;
	t12 += v * b10;
	t13 += v * b11;
	t14 += v * b12;
	t15 += v * b13;
	t16 += v * b14;
	t17 += v * b15;
	v = a[3];
	t3 += v * b0;
	t4 += v * b1;
	t5 += v * b2;
	t6 += v * b3;
	t7 += v * b4;
	t8 += v * b5;
	t9 += v * b6;
	t10 += v * b7;
	t11 += v * b8;
	t12 += v * b9;
	t13 += v * b10;
	t14 += v * b11;
	t15 += v * b12;
	t16 += v * b13;
	t17 += v * b14;
	t18 += v * b15;
	v = a[4];
	t4 += v * b0;
	t5 += v * b1;
	t6 += v * b2;
	t7 += v * b3;
	t8 += v * b4;
	t9 += v * b5;
	t10 += v * b6;
	t11 += v * b7;
	t12 += v * b8;
	t13 += v * b9;
	t14 += v * b10;
	t15 += v * b11;
	t16 += v * b12;
	t17 += v * b13;
	t18 += v * b14;
	t19 += v * b15;
	v = a[5];
	t5 += v * b0;
	t6 += v * b1;
	t7 += v * b2;
	t8 += v * b3;
	t9 += v * b4;
	t10 += v * b5;
	t11 += v * b6;
	t12 += v * b7;
	t13 += v * b8;
	t14 += v * b9;
	t15 += v * b10;
	t16 += v * b11;
	t17 += v * b12;
	t18 += v * b13;
	t19 += v * b14;
	t20 += v * b15;
	v = a[6];
	t6 += v * b0;
	t7 += v * b1;
	t8 += v * b2;
	t9 += v * b3;
	t10 += v * b4;
	t11 += v * b5;
	t12 += v * b6;
	t13 += v * b7;
	t14 += v * b8;
	t15 += v * b9;
	t16 += v * b10;
	t17 += v * b11;
	t18 += v * b12;
	t19 += v * b13;
	t20 += v * b14;
	t21 += v * b15;
	v = a[7];
	t7 += v * b0;
	t8 += v * b1;
	t9 += v * b2;
	t10 += v * b3;
	t11 += v * b4;
	t12 += v * b5;
	t13 += v * b6;
	t14 += v * b7;
	t15 += v * b8;
	t16 += v * b9;
	t17 += v * b10;
	t18 += v * b11;
	t19 += v * b12;
	t20 += v * b13;
	t21 += v * b14;
	t22 += v * b15;
	v = a[8];
	t8 += v * b0;
	t9 += v * b1;
	t10 += v * b2;
	t11 += v * b3;
	t12 += v * b4;
	t13 += v * b5;
	t14 += v * b6;
	t15 += v * b7;
	t16 += v * b8;
	t17 += v * b9;
	t18 += v * b10;
	t19 += v * b11;
	t20 += v * b12;
	t21 += v * b13;
	t22 += v * b14;
	t23 += v * b15;
	v = a[9];
	t9 += v * b0;
	t10 += v * b1;
	t11 += v * b2;
	t12 += v * b3;
	t13 += v * b4;
	t14 += v * b5;
	t15 += v * b6;
	t16 += v * b7;
	t17 += v * b8;
	t18 += v * b9;
	t19 += v * b10;
	t20 += v * b11;
	t21 += v * b12;
	t22 += v * b13;
	t23 += v * b14;
	t24 += v * b15;
	v = a[10];
	t10 += v * b0;
	t11 += v * b1;
	t12 += v * b2;
	t13 += v * b3;
	t14 += v * b4;
	t15 += v * b5;
	t16 += v * b6;
	t17 += v * b7;
	t18 += v * b8;
	t19 += v * b9;
	t20 += v * b10;
	t21 += v * b11;
	t22 += v * b12;
	t23 += v * b13;
	t24 += v * b14;
	t25 += v * b15;
	v = a[11];
	t11 += v * b0;
	t12 += v * b1;
	t13 += v * b2;
	t14 += v * b3;
	t15 += v * b4;
	t16 += v * b5;
	t17 += v * b6;
	t18 += v * b7;
	t19 += v * b8;
	t20 += v * b9;
	t21 += v * b10;
	t22 += v * b11;
	t23 += v * b12;
	t24 += v * b13;
	t25 += v * b14;
	t26 += v * b15;
	v = a[12];
	t12 += v * b0;
	t13 += v * b1;
	t14 += v * b2;
	t15 += v * b3;
	t16 += v * b4;
	t17 += v * b5;
	t18 += v * b6;
	t19 += v * b7;
	t20 += v * b8;
	t21 += v * b9;
	t22 += v * b10;
	t23 += v * b11;
	t24 += v * b12;
	t25 += v * b13;
	t26 += v * b14;
	t27 += v * b15;
	v = a[13];
	t13 += v * b0;
	t14 += v * b1;
	t15 += v * b2;
	t16 += v * b3;
	t17 += v * b4;
	t18 += v * b5;
	t19 += v * b6;
	t20 += v * b7;
	t21 += v * b8;
	t22 += v * b9;
	t23 += v * b10;
	t24 += v * b11;
	t25 += v * b12;
	t26 += v * b13;
	t27 += v * b14;
	t28 += v * b15;
	v = a[14];
	t14 += v * b0;
	t15 += v * b1;
	t16 += v * b2;
	t17 += v * b3;
	t18 += v * b4;
	t19 += v * b5;
	t20 += v * b6;
	t21 += v * b7;
	t22 += v * b8;
	t23 += v * b9;
	t24 += v * b10;
	t25 += v * b11;
	t26 += v * b12;
	t27 += v * b13;
	t28 += v * b14;
	t29 += v * b15;
	v = a[15];
	t15 += v * b0;
	t16 += v * b1;
	t17 += v * b2;
	t18 += v * b3;
	t19 += v * b4;
	t20 += v * b5;
	t21 += v * b6;
	t22 += v * b7;
	t23 += v * b8;
	t24 += v * b9;
	t25 += v * b10;
	t26 += v * b11;
	t27 += v * b12;
	t28 += v * b13;
	t29 += v * b14;
	t30 += v * b15;

	t0 += 38 * t16;
	t1 += 38 * t17;
	t2 += 38 * t18;
	t3 += 38 * t19;
	t4 += 38 * t20;
	t5 += 38 * t21;
	t6 += 38 * t22;
	t7 += 38 * t23;
	t8 += 38 * t24;
	t9 += 38 * t25;
	t10 += 38 * t26;
	t11 += 38 * t27;
	t12 += 38 * t28;
	t13 += 38 * t29;
	t14 += 38 * t30;
	// t15 left as is

	// first car
	c = 1;
	v = t0 + c + 65535;
	c = Math.floor(v / 65536);
	t0 = v - c * 65536;
	v = t1 + c + 65535;
	c = Math.floor(v / 65536);
	t1 = v - c * 65536;
	v = t2 + c + 65535;
	c = Math.floor(v / 65536);
	t2 = v - c * 65536;
	v = t3 + c + 65535;
	c = Math.floor(v / 65536);
	t3 = v - c * 65536;
	v = t4 + c + 65535;
	c = Math.floor(v / 65536);
	t4 = v - c * 65536;
	v = t5 + c + 65535;
	c = Math.floor(v / 65536);
	t5 = v - c * 65536;
	v = t6 + c + 65535;
	c = Math.floor(v / 65536);
	t6 = v - c * 65536;
	v = t7 + c + 65535;
	c = Math.floor(v / 65536);
	t7 = v - c * 65536;
	v = t8 + c + 65535;
	c = Math.floor(v / 65536);
	t8 = v - c * 65536;
	v = t9 + c + 65535;
	c = Math.floor(v / 65536);
	t9 = v - c * 65536;
	v = t10 + c + 65535;
	c = Math.floor(v / 65536);
	t10 = v - c * 65536;
	v = t11 + c + 65535;
	c = Math.floor(v / 65536);
	t11 = v - c * 65536;
	v = t12 + c + 65535;
	c = Math.floor(v / 65536);
	t12 = v - c * 65536;
	v = t13 + c + 65535;
	c = Math.floor(v / 65536);
	t13 = v - c * 65536;
	v = t14 + c + 65535;
	c = Math.floor(v / 65536);
	t14 = v - c * 65536;
	v = t15 + c + 65535;
	c = Math.floor(v / 65536);
	t15 = v - c * 65536;
	t0 += c - 1 + 37 * (c - 1);

	// second car
	c = 1;
	v = t0 + c + 65535;
	c = Math.floor(v / 65536);
	t0 = v - c * 65536;
	v = t1 + c + 65535;
	c = Math.floor(v / 65536);
	t1 = v - c * 65536;
	v = t2 + c + 65535;
	c = Math.floor(v / 65536);
	t2 = v - c * 65536;
	v = t3 + c + 65535;
	c = Math.floor(v / 65536);
	t3 = v - c * 65536;
	v = t4 + c + 65535;
	c = Math.floor(v / 65536);
	t4 = v - c * 65536;
	v = t5 + c + 65535;
	c = Math.floor(v / 65536);
	t5 = v - c * 65536;
	v = t6 + c + 65535;
	c = Math.floor(v / 65536);
	t6 = v - c * 65536;
	v = t7 + c + 65535;
	c = Math.floor(v / 65536);
	t7 = v - c * 65536;
	v = t8 + c + 65535;
	c = Math.floor(v / 65536);
	t8 = v - c * 65536;
	v = t9 + c + 65535;
	c = Math.floor(v / 65536);
	t9 = v - c * 65536;
	v = t10 + c + 65535;
	c = Math.floor(v / 65536);
	t10 = v - c * 65536;
	v = t11 + c + 65535;
	c = Math.floor(v / 65536);
	t11 = v - c * 65536;
	v = t12 + c + 65535;
	c = Math.floor(v / 65536);
	t12 = v - c * 65536;
	v = t13 + c + 65535;
	c = Math.floor(v / 65536);
	t13 = v - c * 65536;
	v = t14 + c + 65535;
	c = Math.floor(v / 65536);
	t14 = v - c * 65536;
	v = t15 + c + 65535;
	c = Math.floor(v / 65536);
	t15 = v - c * 65536;
	t0 += c - 1 + 37 * (c - 1);

	o[0] = t0;
	o[1] = t1;
	o[2] = t2;
	o[3] = t3;
	o[4] = t4;
	o[5] = t5;
	o[6] = t6;
	o[7] = t7;
	o[8] = t8;
	o[9] = t9;
	o[10] = t10;
	o[11] = t11;
	o[12] = t12;
	o[13] = t13;
	o[14] = t14;
	o[15] = t15;
}

function car25519(o: Float64Array) {
	let i,
		v,
		c = 1;
	for (i = 0; i < 16; i++) {
		v = o[i] + c + 65535;
		c = Math.floor(v / 65536);
		o[i] = v - c * 65536;
	}
	o[0] += c - 1 + 37 * (c - 1);
}

function sel25519(p: Float64Array, q: Float64Array, b: number) {
	let t,
		c = ~(b - 1);
	for (let i = 0; i < 16; i++) {
		t = c & (p[i] ^ q[i]);
		p[i] ^= t;
		q[i] ^= t;
	}
}

function pack25519(o: Uint8Array, n: Float64Array) {
	let i, j, b;
	const m = gf(),
		t = gf();
	for (i = 0; i < 16; i++) t[i] = n[i];
	car25519(t);
	car25519(t);
	car25519(t);
	for (j = 0; j < 2; j++) {
		m[0] = t[0] - 0xffed;
		for (i = 1; i < 15; i++) {
			m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
			m[i - 1] &= 0xffff;
		}
		m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
		b = (m[15] >> 16) & 1;
		m[14] &= 0xffff;
		sel25519(t, m, 1 - b);
	}
	for (i = 0; i < 16; i++) {
		o[2 * i] = t[i] & 0xff;
		o[2 * i + 1] = t[i] >> 8;
	}
}

// Converts Curve25519 public key back to Ed25519 public key.
// edwardsY = (montgomeryX - 1) / (montgomeryX + 1)
export function crypto_sign_curve25519_pk_to_ed25519(pk: Uint8Array) {
	const z = new Uint8Array(32),
		x = gf(),
		a = gf(),
		b = gf(),
		gf1 = gf([1]);

	unpack25519(x, pk);

	A(a, x, gf1);
	Z(b, x, gf1);
	inv25519(a, a);
	M(a, a, b);

	pack25519(z, a);
	return z;
}

export function crypto_core_ed25519_scalar_reduce(scalar: Uint8Array): Uint8Array {
	const scalarNum = bytesToNumberLE(scalar);
	const result = mod(scalarNum, ed25519.Point.Fn.ORDER);

	return numberToBytesLE(result, 32);
}
