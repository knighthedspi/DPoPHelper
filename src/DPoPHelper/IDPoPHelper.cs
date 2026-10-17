using OutSystems.ExternalLibraries.SDK;

namespace DPoPHelper;

/// <summary>
/// DPoP proof generation for outbound OAuth 2.0 / OIDC calls (RFC 9449).
/// </summary>
[OSInterface(
    Name = "DPoPHelper",
    Description = "Creates RFC 9449 DPoP proof JWTs for outbound Singpass FAPI 2.0 calls.")]
public interface IDPoPHelper
{
    /// <summary>
    /// Builds and signs a DPoP proof JWT for a single outbound HTTP request.
    /// </summary>
    /// <remarks>
    /// A proof is single-use and bound to one method/URL pair. Generate a fresh one
    /// immediately before every request, including each retry.
    /// </remarks>
    [OSAction(
        Description = "Builds and signs one single-use DPoP proof JWT (RFC 9449) for an outbound request.",
        ReturnName = "ProofJWT",
        ReturnDescription = "The signed DPoP proof in JWS compact serialization.")]
    string CreateDPoPProof(
        [OSParameter(Description = "Full private JWK JSON including the \"d\" member. Used only for signing; never transmitted.")]
        string privateKeyJWK,

        [OSParameter(Description = "Public-only JWK JSON (kty, crv, x, y). Embedded in the proof header as \"jwk\".")]
        string publicKeyJWK,

        [OSParameter(Description = "HTTP method of the request the proof is bound to, e.g. \"POST\" or \"GET\".")]
        string hTM,

        [OSParameter(Description = "Target URL. Any query string or fragment is stripped automatically.")]
        string hTU,

        [OSParameter(Description = "Unique token identifier. Must be a fresh value for every single request.")]
        string jTI,

        [OSParameter(Description = "Issued-at time in Unix epoch seconds.")]
        long iAT,

        [OSParameter(Description = "base64url(SHA-256(access_token)). Required for userinfo; pass an empty string otherwise.")]
        string aTH);
}
