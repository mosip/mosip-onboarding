# AGENTS.md — certs/

Parent guide: [`../AGENTS.md`](../AGENTS.md)

## Purpose

Sample/default root and client certificates for onboarding modules
(`abis`, `mpartner-default-mobile`, `print`), plus the OpenSSL/shell
tooling used to generate or convert them. **These are test/reference
certs, not for production** — `create-signing-certs.sh`'s own header
says so explicitly.

## Layout

```text
certs/
├── README.md                        # one-line note: keep *-inline.pem in sync with its .pem sibling
├── abis/                              client.pem, client-inline.pem, root-ca.pem, root-ca-inline.pem
├── mpartner-default-mobile/             client.pem, client-inline.pem, root-ca.pem, root-ca-inline.pem
├── print/                                 client.pem, client-inline.pem, root-ca.pem, root-ca-inline.pem
├── client-openssl.cnf, root-openssl.cnf     # OpenSSL config templates used by the create-signing-certs scripts
├── demo-oidc-policy.json                      # sample OIDC policy JSON
├── convert.sh                                   # exports a cert from a keystore and converts its public key to JWK
├── create-jwks.sh                                 # fetches the current cert from a live keymanager and converts to JWK
├── create-signing-certs.sh                          # generates a self-signed root+client cert pair (2048-bit RSA) — reference/test only
└── create-signing-certs(4096).sh                      # same as above, 4096-bit RSA keys instead of 2048
```

## Key scripts

- **`create-signing-certs.sh`** / **`create-signing-certs(4096).sh`** —
  generate a self-signed root CA and client certificate for a partner
  (`PARTNER_KC_USERNAME` env var), using `root-openssl.cnf`/
  `client-openssl.cnf`. The two files are identical except for RSA key
  size (2048 vs. 4096 bits) — if you fix a bug in one, apply the same
  fix to the other; they are not generated from a shared template.
- **`convert.sh`** — given a partner's keystore (`keystore.p12` under
  `<path>/certs/<partner>/`) and a password read from a local `key.pwd`
  file, exports the client cert, converts its public key to JWK format
  (via the `pem-jwk` npm tool), and writes `publickey.jwk` back into
  that partner's cert directory.
- **`create-jwks.sh`** — authenticates against a live MOSIP Authmanager/
  Keymanager (`mosip-api-internal-host` env var,
  `mosip_deployment_client_secret` env var) to fetch the **current
  server-side certificate** for `RESIDENT`, then converts its public
  key to JWK. This one talks to a real running environment, unlike
  `convert.sh` and the `create-signing-certs*.sh` scripts, which only
  operate on local files.

## Configuration

- `*-inline.pem` files are the same certificate as their sibling
  `.pem` file, flattened to a single line with literal `\n` escapes —
  regenerate one from the other with `convert.sh` (or by hand) whenever
  either changes; they are not auto-synced.
- `create-jwks.sh` and `convert.sh` both depend on the `pem-jwk` npm
  package being installed globally (`npm install -g pem-jwk`, commented
  out in both scripts — install it yourself before running them).
- No real credentials belong in this directory — `create-jwks.sh`'s
  `mosip_deployment_client_secret` and `convert.sh`'s `key.pwd` file
  are supplied locally at runtime, never committed.

## Agent rules

### Do

1. Update the matching `*-inline.pem` whenever you change a `.pem` file
   in this directory (see root `AGENTS.md`).
2. Apply any fix made in `create-signing-certs.sh` to
   `create-signing-certs(4096).sh` too, and vice versa — they're
   maintained as two near-duplicate files, not one shared script.
3. Treat certs generated here as test/reference material — never point
   these scripts at a production MOSIP environment's real signing keys.

### Do not

1. Do not commit a real `key.pwd`, keystore, or `mosip_deployment_client_secret`
   value used by `convert.sh`/`create-jwks.sh`.
2. Do not assume `create-jwks.sh` is a local-only tool — it makes real
   HTTP calls to `mosip-api-internal-host` and requires a reachable,
   authenticated MOSIP environment.
