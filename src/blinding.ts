import { hexToBytes } from "@noble/curves/utils.js";
import { SessionValidationError, SessionValidationErrorCode } from "@session.js/errors";
import { multiplyPointToScalar, curve25519ToEd25519, ed25519ToCurve25519 } from "./scalar-math";
import { getBlindingK, hexRegex, keyToSessionId } from "./utils";

export function blindKey15({
	ed25519PublicKey,
	serverPublicKey,
}: {
	ed25519PublicKey: Uint8Array;
	serverPublicKey: Uint8Array;
}): Uint8Array {
	const blindingKInput = serverPublicKey;
	const k = getBlindingK(blindingKInput);

	const kA = multiplyPointToScalar(k, ed25519PublicKey);

	return kA;
}

export function blindKey25({
	x25519PublicKey,
	ed25519PublicKey,
	serverPublicKey,
}: {
	x25519PublicKey: Uint8Array;
	ed25519PublicKey: Uint8Array;
	serverPublicKey: Uint8Array;
}): Uint8Array {
	const blindingKInput = new Uint8Array([0x05, ...x25519PublicKey, ...serverPublicKey]);
	const k = getBlindingK(blindingKInput);

	const kA = multiplyPointToScalar(k, ed25519PublicKey);

	return kA;
}

export function blindSessionId(
	options: {
		ed25519PublicKey: Uint8Array;
	} & {
		sogsPublicKey: string | Uint8Array;
		type: "15" | "25";
	},
): string;
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
): [string, string];
export function blindSessionId(
	options: (
		| {
				sessionId: string;
		  }
		| {
				x25519PublicKey: Uint8Array;
		  }
		| {
				ed25519PublicKey: Uint8Array;
		  }
	) & {
		sogsPublicKey: string | Uint8Array;
		type: "15" | "25";
	},
): [string, string] | string {
	let x25519PublicKey: Uint8Array;
	let serverPublicKey: Uint8Array;
	let ed25519PublicKey: Uint8Array;

	if ("ed25519PublicKey" in options) {
		if (options.ed25519PublicKey.length !== 32) {
			throw new SessionValidationError({
				code: SessionValidationErrorCode.InvalidOptions,
				message: "ed25519PublicKey must be 32 bytes long",
			});
		}
		ed25519PublicKey = options.ed25519PublicKey;
		x25519PublicKey = ed25519ToCurve25519(ed25519PublicKey);
	} else {
		if ("sessionId" in options) {
			if (!hexRegex.test(options.sessionId) || options.sessionId.length % 2 !== 0) {
				throw new SessionValidationError({
					code: SessionValidationErrorCode.InvalidSessionID,
					message: "Session ID must be a hex string",
				});
			}
			const sessionIdBytes = hexToBytes(options.sessionId);
			if (sessionIdBytes.length !== 33) {
				throw new SessionValidationError({
					code: SessionValidationErrorCode.InvalidSessionID,
					message: "Session ID must be 33 bytes long",
				});
			}
			if (sessionIdBytes[0] !== 0x05) {
				throw new SessionValidationError({
					code: SessionValidationErrorCode.InvalidSessionID,
					message: "Session ID must start with 05 to blind it",
				});
			}
			x25519PublicKey = sessionIdBytes.subarray(1);
		} else {
			if (options.x25519PublicKey.length !== 32) {
				throw new SessionValidationError({
					code: SessionValidationErrorCode.InvalidOptions,
					message: "x25519PublicKey must be 32 bytes long",
				});
			}
			x25519PublicKey = options.x25519PublicKey;
		}

		ed25519PublicKey = curve25519ToEd25519(x25519PublicKey);
	}

	if (typeof options.sogsPublicKey === "string") {
		if (!hexRegex.test(options.sogsPublicKey) || options.sogsPublicKey.length % 2 !== 0) {
			throw new SessionValidationError({
				code: SessionValidationErrorCode.InvalidOptions,
				message: "sogsPublicKey must be a 64-character hex string",
			});
		}
		serverPublicKey = hexToBytes(options.sogsPublicKey);
	} else {
		serverPublicKey = options.sogsPublicKey;
	}
	if (serverPublicKey.length !== 32) {
		throw new SessionValidationError({
			code: SessionValidationErrorCode.InvalidOptions,
			message: "sogsPublicKey must be 32 bytes long",
		});
	}

	let kA: Uint8Array;
	if (options.type === "15") {
		kA = blindKey15({ ed25519PublicKey, serverPublicKey });
	} else if (options.type === "25") {
		kA = blindKey25({ x25519PublicKey, ed25519PublicKey, serverPublicKey });
	} else {
		throw new SessionValidationError({
			code: SessionValidationErrorCode.InvalidOptions,
			message: "type must be either '15' or '25' for blindSessionId",
		});
	}

	const prefix = options.type === "15" ? 0x15 : 0x25;
	const ftSessionId = (kA: Uint8Array) => keyToSessionId(prefix, kA);

	if ("ed25519PublicKey" in options) {
		return ftSessionId(kA);
	} else {
		const kA2 = new Uint8Array(32);
		kA2.set(kA);
		kA2[31] = kA[31] ^ 0b1000_0000;
		return [ftSessionId(kA), ftSessionId(kA2)];
	}
}
