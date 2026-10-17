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
        string aTH,

        [OSParameter(Description = "Server-supplied DPoP nonce from a DPoP-Nonce response header. Pass an empty string on the first attempt.")]
        string nonce = "");

    /// <summary>
    /// POSTs a form-encoded body with a DPoP proof header and returns the response
    /// together with any DPoP-Nonce the server supplied.
    /// </summary>
    /// <remarks>
    /// Exists because the platform HTTP actions surface the response body and status
    /// but not response headers, and the RFC 9449 nonce handshake is driven entirely
    /// by the DPoP-Nonce response header. Endpoint-agnostic: use for PAR and token.
    /// <para>
    /// Non-2xx responses are returned, not thrown — the caller branches on StatusCode,
    /// because a 400 carrying "use_dpop_nonce" is a normal part of the handshake.
    /// Only transport failures (DNS, TLS, timeout) raise an exception.
    /// </para>
    /// </remarks>
    [OSAction(
        Description = "POSTs a form body with a DPoP header and returns status, body and the DPoP-Nonce response header.")]
    void PostWithDPoP(
        [OSParameter(Description = "Absolute URL to POST to.")]
        string uRL,

        [OSParameter(Description = "Request body, already encoded to match ContentType.")]
        string body,

        [OSParameter(Description = "The DPoP proof JWT for this request, sent as the DPoP header.")]
        string dPoPProof,

        [OSParameter(Description = "HTTP status code of the response.")]
        out int statusCode,

        [OSParameter(Description = "Raw response body.")]
        out string responseBody,

        [OSParameter(Description = "Value of the DPoP-Nonce response header, or empty when absent.")]
        out string dPoPNonce,

        [OSParameter(Description = "Content-Type of the request body.")]
        string contentType = "application/x-www-form-urlencoded",

        [OSParameter(Description = "Request timeout in seconds.")]
        int timeoutSeconds = 30);
}
