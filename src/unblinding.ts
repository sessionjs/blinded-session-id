import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, numberToBytesLE, hexToBytes } from "@noble/curves/utils.js";
import { SessionValidationError, SessionValidationErrorCode } from "@session.js/errors";
import { crypto_scalarmult_ed25519_noclamp } from "./scalar-math";
import { getBlindingK, hexRegex, keyToSessionId } from "./utils";

export function unblindKey15({
	blindedKey,
	serverPublicKey,
}: {
	blindedKey: Uint8Array;
	serverPublicKey: Uint8Array;
}) {
	const blindingKInput = serverPublicKey;
	const k = getBlindingK(blindingKInput);
	const kInverted = numberToBytesLE(ed25519.Point.Fn.inv(bytesToNumberLE(k)), 32);

	const kA = crypto_scalarmult_ed25519_noclamp(kInverted, blindedKey);

	const x25519PublicKey = ed25519.utils.toMontgomery(kA);

	return x25519PublicKey;
}

export function unblindSessionId({
	sessionId,
	sogsPublicKey,
}: {
	sessionId: string | Uint8Array;
	sogsPublicKey: string | Uint8Array;
}) {
	let sessionIdBytes: Uint8Array;
	if (typeof sessionId === "string") {
		if (!hexRegex.test(sessionId) || sessionId.length % 2 !== 0) {
			throw new SessionValidationError({
				code: SessionValidationErrorCode.InvalidSessionID,
				message: "Session ID must be a hex string",
			});
		}
		sessionIdBytes = hexToBytes(sessionId);
	} else {
		sessionIdBytes = sessionId;
	}
	if (sessionIdBytes.length !== 33) {
		throw new SessionValidationError({
			code: SessionValidationErrorCode.InvalidSessionID,
			message: "Session ID must be 33 bytes long",
		});
	}
	const prefix = sessionIdBytes[0];
	if (prefix !== 0x15) {
		throw new SessionValidationError({
			code: SessionValidationErrorCode.InvalidSessionID,
			message: "Only 15-prefixed Session IDs can be unblinded with this function",
		});
	}
	const blindedKey = sessionIdBytes.subarray(1);

	let serverPublicKey: Uint8Array;
	if (typeof sogsPublicKey === "string") {
		serverPublicKey = hexToBytes(sogsPublicKey);
	} else {
		serverPublicKey = sogsPublicKey;
	}
	if (serverPublicKey.length !== 32) {
		throw new SessionValidationError({
			code: SessionValidationErrorCode.InvalidOptions,
			message: "sogsPublicKey must be 32 bytes long",
		});
	}

	const ftSessionId = (kA: Uint8Array) => keyToSessionId(0x05, kA);

	if (prefix === 0x15) {
		const x25519PublicKey = unblindKey15({
			blindedKey,
			serverPublicKey,
		});
		return ftSessionId(x25519PublicKey);
	}
}
