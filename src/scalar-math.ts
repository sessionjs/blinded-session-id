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

export function multiplyPointToScalar(scalar: Uint8Array, point: Uint8Array): Uint8Array {
	const L = ed25519.Point.Fn.ORDER;
	const s = mod(bytesToNumberLE(scalar), L);

	const P = ed25519.Point.fromBytes(point);
	if (P.isSmallOrder()) {
		throw new Error("scalarMultEd25519NoClamp: invalid point (small order)");
	}

	return P.multiply(s).toBytes();
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
