# @session.js/blinded-session-id

Utility JavaScript library with methods to work with Session's blinded Session ID.

Example of normal Session ID:
`057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b`

Example of blinded Session ID:
`15d9fd3a6c3c5ddf7500b862174f205ab27164232d9b10fe31f145e61629b676e3`

Blinded IDs are used on Session SOGS to conceal identity of room's users.

## Usage

```ts
import { blindSessionId } from '@session.js/blinded-session-id'

await blindSessionId({
  sessionId: '057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b',
  serverPk: 'cb4fd6199b84dc3664f0373354341a01007ecaa99a388496fe8775b9b76a253b'
}) // => 15383d0a3ba605abe3b5b7343102be3fc0026056b9812e06f6daee3be62a6a56e3
```

## Advanced use

- generateBlindedIds — returns legacy and modern blinded id
- generateKAs — returns legacy and modern KAs as Uint8Array
- convertToX25519Key, convertToEd25519Key — self explanatory

## Credit

Credit to li0ard, this code was mostly taken from [https://github.com/theinfinityway/session_id/](https://github.com/theinfinityway/session_id/)

## Made for session.js

Use Session messenger programmatically with [Session.js](https://github.com/sessionjs/client): Session bots, custom Session clients, and more.

## Donate

[hloth.dev/donate](https://hloth.dev/donate) · Tor: [hlothdevzkti6suoksy7lcy7hmpxnr3msu5waokzaslsi2mnx5ouu4qd.onion/donate](http://hlothdevzkti6suoksy7lcy7hmpxnr3msu5waokzaslsi2mnx5ouu4qd.onion/donate)

## License

[MIT](./LICENSE)