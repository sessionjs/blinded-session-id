# @session.js/blinded-session-id

Utility JavaScript library with methods to work with Session's blinded Session ID. Uses [noble v2](https://www.npmjs.com/package/@noble/ciphers) under the hood.

Example of unblinded Session ID (05-prefixed):
`057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b`

Example of blinded Session ID (15-prefixed):
`15d9fd3a6c3c5ddf7500b862174f205ab27164232d9b10fe31f145e61629b676e3`

Blinded IDs are used on Session SOGS to conceal identity of room's users.

## Usage

### Blinding

To "blind" Session ID, we need the Sesion ID itself and the SOGS's public key (the part after `?public_key=` in the SOGS url).

```ts
import { blindSessionId } from '@session.js/blinded-session-id'

await blindSessionId({
  sessionId: '057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b',
  serverPk: 'cb4fd6199b84dc3664f0373354341a01007ecaa99a388496fe8775b9b76a253b'
}) // => [
// 			"15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3",
// 			"15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3"
//		]
```

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

<b>TL;DR: When converting Session's x25519 (Session ID) to the ed25519 key (needed for blinding), the sign (+/-) information is lost, producing two equally valid possibilities.</b>

More on blinding: <a href="https://blog.li0ard.rest/blindedid">“Blinded ID в Session и что с ними не так” by li0ard</a>
</details>

```ts

```

```ts
import { unblindSessionId } from '@session.js/blinded-session-id'

await unblindSessionId({
  sessionId: '15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3',
  serverPk: 'cb4fd6199b84dc3664f0373354341a01007ecaa99a388496fe8775b9b76a253b'
}) // => 057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b
```

## Advanced use

- generateBlindedIds — returns legacy and modern blinded id
- generateKAs — returns legacy and modern KAs as Uint8Array
- convertToX25519Key, convertToEd25519Key — self explanatory

## Acknowledgements

Credit to li0ard for [https://github.com/theinfinityway/session_id/](https://github.com/theinfinityway/session_id/) (MIT license)

Credit to [xHD-Wallet-API-ts](https://github.com/algorandfoundation/xHD-Wallet-API-ts) for scalar multiplication functions implementations (Apache-2.0 license)

## Made for Session.js

Use Session messenger programmatically with [Session.js](https://git.hloth.dev/session.js/client): Session bots, custom Session clients, and more.

## Donate

[hloth.dev/donate](https://hloth.dev/donate) · Tor: [hlothdevzkti6suoksy7lcy7hmpxnr3msu5waokzaslsi2mnx5ouu4qd.onion/donate](http://hlothdevzkti6suoksy7lcy7hmpxnr3msu5waokzaslsi2mnx5ouu4qd.onion/donate)

## License

[MIT](./LICENSE)