import { expect, test, describe } from "bun:test";
import { blindSessionId } from "../src/index";

describe("15-prefixed", () => {
	test("hloth in custom SOGS", () => {
		expect(
			blindSessionId({
				sessionId: "057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b",
				sogsPublicKey: "cb4fd6199b84dc3664f0373354341a01007ecaa99a388496fe8775b9b76a253b",
				type: "15",
			}),
		).toContain("15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3");
	});
	test("KeeJef in Poweruser Feedback SOGS", () => {
		expect(
			blindSessionId({
				sessionId: "05d871fc80ca007eed9b2f4df72853e2a2d5465a92fcb1889fb5c84aa2833b3b40",
				sogsPublicKey: "39016f991400c35a46e11e06cb2a64d6d8ab6652e484a556b14f7cf57ed7e73a",
				type: "15",
			}),
		).toContain("1583d48386fe3adf2ff0707bcea0c028cf9eea1876e5f723fba359a24a0858fdd5");
	});
	test("KeeJef in Session SOGS", () => {
		expect(
			blindSessionId({
				sessionId: "05d871fc80ca007eed9b2f4df72853e2a2d5465a92fcb1889fb5c84aa2833b3b40",
				sogsPublicKey: "a03c383cf63c3c4efe67acc52112a6dd734b3a946b9545f488aaa93da7991238",
				type: "15",
			}),
		).toContain("15c6807a9933310392a26de0cf9635fba1535b2b9296c9eb6a060481d51b8983a7");
	});
	test("Ivan in Russian SOGS", () => {
		expect(
			blindSessionId({
				sessionId: "052c4eab9297e26af618df469b87aaee2d2a8db45eb42c9d6a8d48768425f5bb65",
				sogsPublicKey: "118df8c6c471ac0468c7c77e1cdc12f24a139ee8a07c6e3bf4e7855640dad821",
				type: "15",
			}),
		).toContain("153645531fb118086b5a5c0a6c92cbb8e65b30daa10e2ef6857683ffe05fc25194");
	});
	test("gravel in session SOGS", () => {
		expect(
			blindSessionId({
				sessionId: "05d59dd03e98af346c21a479125b8d17b4ea05942a4c0632a51e7fe3d78990cd27",
				sogsPublicKey: "a03c383cf63c3c4efe67acc52112a6dd734b3a946b9545f488aaa93da7991238",
				type: "15",
			}),
		).toContain("15d1b5f471ebcb72b703d765cf5814ba5f7de9db09a96c59cd9f499087b0c8cc06");
	});
	test("gravel in pu SOGS", () => {
		expect(
			blindSessionId({
				sessionId: "05d59dd03e98af346c21a479125b8d17b4ea05942a4c0632a51e7fe3d78990cd27",
				sogsPublicKey: "39016f991400c35a46e11e06cb2a64d6d8ab6652e484a556b14f7cf57ed7e73a",
				type: "15",
			}),
		).toContain("15a507e901b27d2f85606fd73f082f25ec79f0a92bd5efc586cd1c005f3ab56170");
	});
	test("hloth in custom SOGS 2", () => {
		expect(
			blindSessionId({
				sessionId: "057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b",
				sogsPublicKey: "ac9c872e525a58970df6971655abb944a30b38853442a793b29843d20795e840",
				type: "15",
			}),
		).toContain("15264c132e2e72a9c50b7a981eac11a48b3e51ae5a0ea45ea47deb519a3fa76612");
	});
	test("custom blinded id", () => {
		expect(
			blindSessionId({
				sessionId: "057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b",
				sogsPublicKey: "cb4fd6199b84dc3664f0373354341a01007ecaa99a388496fe8775b9b76a253b",
				type: "15",
			}),
		).toContain("15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3");
	});
	test("custom blinded id", () => {
		expect(
			blindSessionId({
				sessionId: "057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b",
				sogsPublicKey: "cb4fd6199b84dc3664f0373354341a01007ecaa99a388496fe8775b9b76a253b",
				type: "15",
			}),
		).toContain("15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3");
	});
});

describe("25-prefixed", () => {
	expect(
		blindSessionId({
			sessionId: "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f",
			sogsPublicKey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			type: "25",
		}),
	).toContain("253b991dcbba44cfdb45d5b38880d95cff723309e3ece6fd01415ad5fa1dccc7ac");
	expect(
		blindSessionId({
			sessionId: "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f",
			sogsPublicKey: "00cdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			type: "25",
		}),
	).toContain("2598589c7885b56cbeae6ab7b4224f202815520a54995872cb1833b44db6401c8d");
	expect(
		blindSessionId({
			sessionId: "0505c9a9bf178fa644d44bebf628716dc7f2df3d0842e97881962c723699152073",
			sogsPublicKey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			type: "25",
		}),
	).toContain("25a69cc6884530bf8498d22892e563716c4742f2845a7eb608de2aecbe7b6b5996");
});
