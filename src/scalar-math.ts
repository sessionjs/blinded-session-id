import { ed25519 } from "@noble/curves/ed25519.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";

export function scalarAdd(scalarA: Uint8Array, scalarB: Uint8Array): Uint8Array {
	const a = bytesToNumberLE(scalarA);
	const b = bytesToNumberLE(scalarB);
	const result = ed25519.Point.Fn.add(a, b);

	return numberToBytesLE(result, 32);
}

export function scalarMul(scalarA: Uint8Array, scalarB: Uint8Array): Uint8Array {
	const a = bytesToNumberLE(scalarA);
	const b = bytesToNumberLE(scalarB);
	const result = ed25519.Point.Fn.mul(a, b);

	return numberToBytesLE(result, 32);
}

export function scalarReduce(scalar: Uint8Array): Uint8Array {
	const scalarNum = bytesToNumberLE(scalar);
	const result = mod(scalarNum, ed25519.Point.Fn.ORDER);

	return numberToBytesLE(result, 32);
}

export function ed25519ToCurve25519(ed25519Pk: Uint8Array): Uint8Array {
	const seed = ed25519Pk.slice(0, 32);
	return ed25519.utils.toMontgomerySecret(seed);
}

export function curve25519ToEd25519(x25519Pk: Uint8Array): Uint8Array {
	const f = ed25519.Point.Fp;
	const x = f.fromBytes(x25519Pk);

	return f.toBytes(f.div(f.sub(x, f.ONE), f.add(x, f.ONE)));
}

export function scalarMultEd25519NoClamp(scalar: Uint8Array, point: Uint8Array): Uint8Array {
	if (scalar.length !== 32) {
		throw new Error(`scalarMultEd25519NoClamp: expected 32-byte scalar, got ${scalar.length}`);
	}
	if (point.length !== 32) {
		throw new Error(`scalarMultEd25519NoClamp: expected 32-byte point, got ${point.length}`);
	}

	const L = ed25519.Point.Fn.ORDER;
	const s = mod(bytesToNumberLE(scalar), L);

	const P = ed25519.Point.fromBytes(point);
	if (P.isSmallOrder()) {
		throw new Error("crypto_scalarmult_ed25519_noclamp: invalid point (small order)");
	}

	return P.multiply(s).toBytes();
}

export function scalarMultEd25519BaseNoClamp(scalar: Uint8Array): Uint8Array {
	if (scalar.length !== 32) {
		throw new Error(`scalarMultEd25519BaseNoClamp: expected 32-byte scalar, got ${scalar.length}`);
	}

	const L = ed25519.Point.Fn.ORDER;
	const s = mod(bytesToNumberLE(scalar), L);

	const P = ed25519.Point.BASE;

	if (s === 0n) {
		const identity = new Uint8Array(32);
		identity[0] = 1;
		return identity;
	}

	return P.multiply(s).toBytes();
}
