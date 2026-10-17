# DPoPHelper

An OutSystems ODC external library that builds RFC 9449 DPoP proof JWTs for the
outbound Singpass FAPI 2.0 flow in `ODCAuthBrokerFAPI`.

It exists because `Security.JWT_CreateToken` cannot set the JWT header. A DPoP proof
must carry `typ: "dpop+jwt"` and embed the public key as `jwk`, and without the `jwk`
member the authorization server has nothing to verify the signature against.

## The action

`CreateDPoPProof` — one call produces one single-use proof.

| Input | Type | Notes |
|---|---|---|
| `PrivateKeyJWK` | Text | Full JWK JSON including `d`. Used only for signing; never transmitted. |
| `PublicKeyJWK` | Text | Public-only JWK (`kty`, `crv`, `x`, `y`). |
| `HTM` | Text | HTTP method. Upper-cased automatically. |
| `HTU` | Text | Target URL. Query and fragment stripped automatically. |
| `JTI` | Text | Unique per request — a fresh GUID every single call, including retries. |
| `IAT` | Long Integer | Unix epoch seconds. |
| `ATH` | Text | `base64url(SHA-256(access_token))` for userinfo; empty string elsewhere. |

| Output | Type |
|---|---|
| `ProofJWT` | Text |

Produces, for example:

```
header  {"typ":"dpop+jwt","alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":"…","y":"…"}}
payload {"htm":"POST","htu":"https://stg-id.singpass.gov.sg/auth/par","iat":1792203993,"jti":"c0c1811f-…"}
```

### Behaviour worth knowing

- **`alg` follows the key.** P-256 → ES256, P-384 → ES384, P-521 → ES512. The proof can
  never be signed with an algorithm that disagrees with the curve.
- **The `jwk` header is rebuilt from parsed members**, not copied from the input string.
  Passing a private JWK in the `PublicKeyJWK` slot still cannot leak `d`.
- **`jwk` members are in RFC 7638 order** (`crv`, `kty`, `x`, `y`), so the serialized form
  is also the correct input for a JWK thumbprint if a `jkt` is ever needed.
- **`ath` is omitted entirely when empty**, as RFC 9449 requires for non-resource requests.
- **`iat` serializes as an unquoted number.**
- **Mismatched key pairs are rejected locally** with a clear message rather than becoming
  a generic remote rejection.
- The signature is IEEE P1363 (`r‖s`), which is the JWS format — not DER.

### Caller responsibilities

The library deliberately does not own these:

- Generating a new key pair per login session and reusing it across PAR, token and
  userinfo. Never across sessions.
- Generating a fresh `JTI` per request. The library validates presence, not uniqueness.
- Attaching the result as the `DPoP:` HTTP header, and on userinfo also sending
  `Authorization: DPoP <access_token>` — the scheme is `DPoP`, not `Bearer`.

`exp` is not emitted. Singpass treats it as optional and caps it at `iat + 2 minutes`;
proofs are consumed immediately, so omitting it avoids a needless clock-skew failure mode.

## Build

```
dotnet test
./package.ps1
```

`package.ps1` builds, tests, publishes and writes `dist/DPoPHelper.zip` for upload in the
ODC Portal under **External logic**. It refuses to package if tests fail.

## Target framework

Set once in `Directory.Build.props` as `OsTargetFramework`, currently **net10.0**.

`OutSystems.ExternalLibraries.SDK` 1.7.0 ships `net6.0`, `net8.0` and `netstandard2.0`
only, so net10.0 binds through the netstandard2.0 facade. That compiles and tests clean
here, but ODC's External Logic runtime is a fixed version and has historically pinned
.NET 6 then .NET 8. **If the portal rejects the upload or the library faults at runtime,
change `OsTargetFramework` to `net8.0` and rebuild** — nothing else needs to move.

## Verification

`dotnet test` covers 33 cases: the mandatory `typ`/`alg`/`jwk` header, no `d` leakage,
RFC 7638 member ordering, numeric single-occurrence `iat`, `htu` normalization,
conditional `ath`, P1363 signature shape, signature verification against the embedded
`jwk` on all three curves, and input validation.

For an end-to-end check, generate a proof and paste it into the Singpass validator at
<https://developer.singpass.gov.sg/troubleshooting-tool>.
