import { bytesToHex, hexToBytes } from "@noble/curves/utils.js";
import { blake2b } from "@noble/hashes/blake2.js";
import {
	crypto_core_ed25519_scalar_reduce,
	crypto_sign_curve25519_pk_to_ed25519,
	crypto_scalarmult_ed25519_noclamp,
} from "./scalar-math";
import { SessionValidationError, SessionValidationErrorCode } from "@session.js/errors";

function getBlindingK(input: Uint8Array) {
	const serverPkHash = blake2b(input, {
		dkLen: 64,
	});
	const k = crypto_core_ed25519_scalar_reduce(serverPkHash);
	return k;
}

export function blindKey15({
	ed25519PublicKey,
	serverPublicKey,
}: {
	ed25519PublicKey: Uint8Array;
	serverPublicKey: Uint8Array;
}): [Uint8Array, Uint8Array] {
	const blindingKInput = serverPublicKey;
	const k = getBlindingK(blindingKInput);

	const kA = crypto_scalarmult_ed25519_noclamp(k, ed25519PublicKey);

	const kA2 = new Uint8Array(32);
	kA2.set(kA);
	kA2[31] = kA[31] ^ 0b1000_0000;

	return [new Uint8Array([0x15, ...kA]), new Uint8Array([0x15, ...kA2])];
}

export function blindKey25({
	x25519PublicKey,
	ed25519PublicKey,
	serverPublicKey,
}: {
	x25519PublicKey: Uint8Array;
	ed25519PublicKey: Uint8Array;
	serverPublicKey: Uint8Array;
}): [Uint8Array, Uint8Array] {
	const blindingKInput = new Uint8Array([0x05, ...x25519PublicKey, ...serverPublicKey]);
	const k = getBlindingK(blindingKInput);

	const kA = crypto_scalarmult_ed25519_noclamp(ed25519PublicKey, k);

	const kA2 = new Uint8Array(32);
	kA2.set(kA);
	kA2[31] = kA[31] ^ 0b1000_0000;

	return [new Uint8Array([0x25, ...kA]), new Uint8Array([0x25, ...kA2])];
}

export function blindSessionId(
	options: (
		| {
				sessionId: string;
		  }
		| {
				x25519PublicKey: Uint8Array;
		  }
	) & {
		sogsPublicKey: string | Uint8Array;
		type: "15" | "25";
	},
) {
	let x25519PublicKey: Uint8Array;
	if ("sessionId" in options) {
		const sessionIdBytes = hexToBytes(options.sessionId);
		if (sessionIdBytes[0] !== 0x05) {
			throw new SessionValidationError({
				code: SessionValidationErrorCode.InvalidSessionID,
				message: "Session ID must start with 05 to blind it",
			});
		}
		x25519PublicKey = sessionIdBytes.subarray(1);
	} else {
		x25519PublicKey = options.x25519PublicKey;
	}

	let serverPublicKey: Uint8Array;
	if (typeof options.sogsPublicKey === "string") {
		serverPublicKey = hexToBytes(options.sogsPublicKey);
	} else {
		serverPublicKey = options.sogsPublicKey;
	}

	const ed25519PublicKey = crypto_sign_curve25519_pk_to_ed25519(x25519PublicKey);
	if (options.type === "15") {
		const [kA, kA2] = blindKey15({ ed25519PublicKey, serverPublicKey });
		return [bytesToHex(kA), bytesToHex(kA2)];
	} else if (options.type === "25") {
		const [kA, kA2] = blindKey25({ x25519PublicKey, ed25519PublicKey, serverPublicKey });
		return [bytesToHex(kA), bytesToHex(kA2)];
	} else {
		throw new SessionValidationError({
			code: SessionValidationErrorCode.InvalidOptions,
			message: "type must be either '15' or '25' for blindSessionId",
		});
	}
}
