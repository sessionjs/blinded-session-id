# @session.js/blinded-session-id

Utility JavaScript library with methods to work with Session's blinded Session ID. Uses [noble v2](https://www.npmjs.com/package/@noble/ciphers) under the hood.

Example of unblinded Session ID (05-prefixed):
`057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b`

Example of blinded Session ID (15-prefixed):
`15d9fd3a6c3c5ddf7500b862174f205ab27164232d9b10fe31f145e61629b676e3`

Example of blinded Session ID (25-prefixed):
`253b991dcbba44cfdb45d5b38880d95cff723309e3ece6fd01415ad5fa1dccc7ac`

Blinded IDs are used on Session SOGS to conceal identity of room's users.

- [@session.js/blinded-session-id](#sessionjsblinded-session-id)
	- [Usage](#usage)
		- [Blinding](#blinding)
			- [Blinding with Session ID or x25519 public key](#blinding-with-session-id-or-x25519-public-key)
			- [Blinding with ed25519 public key](#blinding-with-ed25519-public-key)
		- [Unblinding](#unblinding)
			- [Unblinding 15-prefixed Session IDs](#unblinding-15-prefixed-session-ids)
			- [Unblinding 25-prefixed Session IDs](#unblinding-25-prefixed-session-ids)
		- [Advanced usage](#advanced-usage)
			- [getBlindingK](#getblindingk)
	- [Acknowledgements](#acknowledgements)
	- [Made for Session.js](#made-for-sessionjs)
	- [Donate](#donate)
	- [License](#license)

## Usage

### Blinding

#### Blinding with Session ID or x25519 public key

To "blind" Session ID, we need the Sesion ID itself and the SOGS's public key (the part after `?public_key=` in the SOGS url).

You have multiple choices on input format. All blindSessionId signatures require `type` property defining type of the output Session ID (15- or 25-prefixed). The simpliest format is passing both sessionId and sogsPublicKey as hex-encoded strings.

You'll get two variants of the blinded Session ID. **Both outputs are valid and possible and there is absolutely no way to determine which one is correct** (unless you have user's ed25519 key, more on that below).

```ts
import { blindSessionId } from "@session.js/blinded-session-id";

blindSessionId({
	type: "15",
	sessionId: "057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b",
	sogsPublicKey: "cb4fd6199b84dc3664f0373354341a01007ecaa99a388496fe8775b9b76a253b",
});
// Either of those will be the blinded ID
// => [
//      "15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a5663",
//      "15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3"
//    ]
```

You can also pass sogsPublicKey as Uint8Array, in case you already have it decoded in your app. You can also pass Session ID as x25519 public key as Uint8Array in case you already have it decoded in your app, but keep in mind that Session ID is 33 bytes long and x25519 public key is 32 bytes long, because Session ID has a prefix byte (0x05, 0x15 or 0x25).

```ts
import { blindSessionId } from "@session.js/blinded-session-id";

blindSessionId({
	type: "15",
	x25519PublicKey: new Uint8Array([
		122, 235, 102, 228, 86, 96, 195, 189, 251, 124, 98, 112, 111, 100, 64, 34, 106, 244, 62, 193,
		63, 59, 111, 137, 156, 29, 212, 219, 27, 143, 206, 91,
	]),
	sogsPublicKey: new Uint8Array([
		203, 79, 214, 25, 155, 132, 220, 54, 100, 240, 55, 51, 84, 52, 26, 1, 0, 126, 202, 169, 154, 56,
		132, 150, 254, 135, 117, 185, 183, 106, 37, 59,
	]),
});
// Either of those will be the blinded ID
// => [
//      "15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a5663",
//      "15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3"
//    ]
```

When converting Session's x25519 (Session ID) to the ed25519 key (needed for blinding), the sign (+/-) information is lost, producing two equally valid possibilities. So unless you have user's ed25519 public key, you cannot have a guaranteed determenistic correct single output for blinding, you will always have to account for two outputs.

<details>
<summary>But why two blinded IDs?</summary>

Hang on tight, we're diving into some real nerdy cryptography here!

You know how Session actually has two keypairs — x25519 (public, secret) and ed25519 (public, secret), all of which are derived from the main secret seed (which can be encoded into words with mnemonic/secret phrase) and Session ID is the public x25519 key?

In order to "blind" Session ID we first calculate a "blinding factor" `k` using modulo of SOGS public key and ed25519's ORDER constant. Then we calculate `kA` by multiplying user's ed25519 public key and `k`. Finally, we convert `kA` to hex and prepend it with `15` to mark it as a "blinded" Session ID.

But wait a second, where did "user's ed25519 public key" come from? Remember, Session ID is a x25519 public key, not ed25519 public key. These are two different keypairs, two different elliptic curves and they behave in very different ways!

That's where the major flaw of Session comes in. Technically, we could just settle on some way of converting value from one curve to another and vice verse. In fact, that's precisely what libsodium (and official Session clients) do using crypto_sign_curve25519_pk_to_ed25519. In the end, both curves are just mathematical curves and translating one to another should be determenistic.

There is just one problem though: x25519 does not have negative values, while ed25519 does have them. So ed25519's `123` converted to x25519 would be `456` and vice-verse, but what happens when we convert ed25519's `-123` to x25519 curve is... `456` too! See the problem? Two different values producing same output. 

And this wouldn't be bad if we only wanted x25519 for blinding, but as you saw earlier, we need ed25519 keys. Now you want to convert x25519 back to ed25519 and only have this x25519 value: `456`. Was it `123` or `-123` in ed25519 that produced that number?

So what happens when we try to convert x25519 public key (Session ID) -> ed25519 public key (for blinding) is that we end up with two keys since we don't know whether ed25519 should be positive or negative.

If only we had user's secret seed (mnemonic), we could easily calculate ed25519 and avoid x25519 -> ed25519 conversion issue at all... But alas, Session IDs are using x25519 and converting x25519 to ed25519 produces two results because of the lost signing bit.

More on blinding: <a href="https://blog.li0ard.rest/blindedid">“Blinded ID в Session и что с ними не так” by li0ard</a>
</details>

#### Blinding with ed25519 public key

If you do have user's ed25519 public key (e.g. you control the secret seed, running from the user's client, etc), you can pass it directly instead of Session ID or x25519PublicKey and get a single, correct blinded ID.

```ts
import { blindSessionId } from "@session.js/blinded-session-id"

blindSessionId({
	type: "15",
	ed25519PublicKey: new Uint8Array([
		240, 55, 163, 9, 91, 114, 247, 212, 93, 217, 12, 245, 213, 114, 251, 182, 195, 95, 46, 4, 211,
		85, 177, 217, 201, 218, 3, 95, 202, 132, 158, 151,
	]),
	sogsPublicKey: "cb4fd6199b84dc3664f0373354341a01007ecaa99a388496fe8775b9b76a253b",
});
// => 15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3
```

There is no way to convert x25519 public key to ed25519 public key without losing the sign bit and thus getting two possible ed25519 keys and two possible blinded Session IDs.

### Unblinding

Unblinding is a security vulnerability [discovered by li0ard](https://blog.li0ard.rest/blindedid) possible because 15-prefixed IDs use SOGS's public key as blake2b hash input, which is publicly known, making it possible to reverse 15-prefixed blinding by using the same sogsPublicKey.

In 25-prefixed IDs this issue was fixed by using both x25519 public key and SOGS's public key as blake2b hash input, so unless you know user's 05-prefixed Session ID it's impossible to unblind 25-prefixed Session ID, and if you do, there is no sense to unblind it anyway.

#### Unblinding 15-prefixed Session IDs

To unblind a Session ID, pass it as `sessionId` and SOGS's public key in either hex-encoded string or as Uint8Array.

```ts
import { unblindSessionId } from "@session.js/blinded-session-id"

unblindSessionId({
	sessionId: "15264c132e2e72a9c50b7a981eac11a48b3e51ae5a0ea45ea47deb519a3fa76612",
	sogsPublicKey: "ac9c872e525a58970df6971655abb944a30b38853442a793b29843d20795e840",
});
// => 057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b
```

#### Unblinding 25-prefixed Session IDs

Unblinding 25-prefixed Session IDs is impossible.

### Advanced usage

#### getBlindingK

generates a hash for blinding/unblinding using blake2b

```ts
import { getBlindingK } from "@session.js/blinded-session-id/utils.js";

const sogsPublicKey = new Uint8Array([
	203, 79, 214, 25, 155, 132, 220, 54, 100, 240, 55, 51, 84, 52, 26, 1, 0, 126, 202, 169, 154, 56,
	132, 150, 254, 135, 117, 185, 183, 106, 37, 59,
]);
getBlindingK(sogsPublicKey);
// => Uint8Array(32) [ 27, 203, 111, 10, 221, 88, 187, 146, 221, 11, 206, 55, 7, 86, 218, 223, 21, 123, 29, 214, 198, 182, 3, 40, 188, 123, 190, 73, 35, 122, 140, 13 ]
```

## Acknowledgements

Credit to li0ard for [https://github.com/theinfinityway/session_id/](https://github.com/theinfinityway/session_id/) (MIT license) and src/scalar-math.ts
## Made for Session.js

Use Session messenger programmatically with [Session.js](https://git.hloth.dev/session.js/client): Session bots, custom Session clients, and more.

## Donate

[hloth.dev/donate](https://hloth.dev/donate) · Tor: [hlothdevzkti6suoksy7lcy7hmpxnr3msu5waokzaslsi2mnx5ouu4qd.onion/donate](http://hlothdevzkti6suoksy7lcy7hmpxnr3msu5waokzaslsi2mnx5ouu4qd.onion/donate)

## License

[MIT](./LICENSE)