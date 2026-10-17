using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DPoPHelper;

/// <inheritdoc cref="IDPoPHelper" />
public sealed class DPoPHelper : IDPoPHelper
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        // base64url and URL values must not be escaped into \u sequences.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false
    };

    /// <inheritdoc />
    public string CreateDPoPProof(
        string privateKeyJWK,
        string publicKeyJWK,
        string hTM,
        string hTU,
        string jTI,
        long iAT,
        string aTH)
    {
        if (string.IsNullOrWhiteSpace(privateKeyJWK))
            throw new ArgumentException("PrivateKeyJWK is required.", nameof(privateKeyJWK));
        if (string.IsNullOrWhiteSpace(publicKeyJWK))
            throw new ArgumentException("PublicKeyJWK is required.", nameof(publicKeyJWK));
        if (string.IsNullOrWhiteSpace(hTM))
            throw new ArgumentException("HTM is required.", nameof(hTM));
        if (string.IsNullOrWhiteSpace(hTU))
            throw new ArgumentException("HTU is required.", nameof(hTU));
        if (string.IsNullOrWhiteSpace(jTI))
            throw new ArgumentException("JTI is required and must be unique per request.", nameof(jTI));

        var privateKey = EcJwk.Parse(privateKeyJWK, nameof(privateKeyJWK), requirePrivate: true);
        var publicKey = EcJwk.Parse(publicKeyJWK, nameof(publicKeyJWK), requirePrivate: false);

        // A proof whose embedded jwk does not match the signing key is unverifiable.
        // Catching it here turns a generic remote rejection into a clear local error.
        if (!privateKey.HasSamePublicPartAs(publicKey))
        {
            throw new ArgumentException(
                "PublicKeyJWK does not match PrivateKeyJWK: the crv/x/y values differ. " +
                "The embedded jwk must be the public half of the signing key.",
                nameof(publicKeyJWK));
        }

        var header = new JsonObject
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = publicKey.JwsAlgorithm,
            // Rebuilt from parsed members rather than echoing the caller's string, so a
            // private JWK passed here by mistake can never leak "d" into the proof.
            // Member order follows RFC 7638 (crv, kty, x, y), which also makes this
            // byte sequence the correct input for a JWK thumbprint.
            ["jwk"] = new JsonObject
            {
                ["crv"] = publicKey.Curve,
                ["kty"] = "EC",
                ["x"] = publicKey.X,
                ["y"] = publicKey.Y
            }
        };

        var payload = new JsonObject
        {
            ["htm"] = hTM.ToUpperInvariant(),
            ["htu"] = NormalizeHtu(hTU),
            ["iat"] = iAT,
            ["jti"] = jTI
        };

        // RFC 9449: ath is required for resource requests and must be absent otherwise.
        if (!string.IsNullOrEmpty(aTH))
            payload["ath"] = aTH;

        var headerSegment = Base64UrlEncode(Serialize(header));
        var payloadSegment = Base64UrlEncode(Serialize(payload));
        var signingInput = Encoding.ASCII.GetBytes(headerSegment + "." + payloadSegment);

        using var ecdsa = privateKey.CreateSigningKey();

        // SignData returns IEEE P1363 (r || s) fixed-width concatenation, which is
        // exactly the JWS ECDSA signature format. Do NOT convert to DER.
        var signature = ecdsa.SignData(signingInput, publicKey.HashAlgorithm);

        return headerSegment + "." + payloadSegment + "." + Base64UrlEncode(signature);
    }

    /// <summary>
    /// RFC 9449 section 4.2: htu is the request URI without query or fragment.
    /// </summary>
    internal static string NormalizeHtu(string htu)
    {
        var value = htu.Trim();

        var cut = value.IndexOfAny(['?', '#']);
        if (cut >= 0)
            value = value[..cut];

        return value;
    }

    private static byte[] Serialize(JsonNode node) =>
        Encoding.UTF8.GetBytes(node.ToJsonString(SerializerOptions));

    internal static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

    internal static byte[] Base64UrlDecode(string value, string memberName)
    {
        var s = value.Replace('-', '+').Replace('_', '/');

        s = (s.Length % 4) switch
        {
            2 => s + "==",
            3 => s + "=",
            0 => s,
            _ => throw new ArgumentException($"JWK member \"{memberName}\" is not valid base64url.")
        };

        try
        {
            return Convert.FromBase64String(s);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException($"JWK member \"{memberName}\" is not valid base64url.", ex);
        }
    }

    /// <summary>
    /// A parsed EC JWK, with the curve-dependent choices (algorithm, hash, coordinate
    /// width) resolved once so the proof cannot be signed with a mismatched alg.
    /// </summary>
    private sealed record EcJwk(
        string Curve,
        string X,
        string Y,
        string? D,
        ECCurve NamedCurve,
        string JwsAlgorithm,
        HashAlgorithmName HashAlgorithm,
        int CoordinateBytes)
    {
        public static EcJwk Parse(string json, string paramName, bool requirePrivate)
        {
            JsonElement root;
            try
            {
                using var doc = JsonDocument.Parse(json);
                root = doc.RootElement.Clone();
            }
            catch (JsonException ex)
            {
                throw new ArgumentException($"{paramName} is not valid JSON.", paramName, ex);
            }

            if (root.ValueKind != JsonValueKind.Object)
                throw new ArgumentException($"{paramName} must be a JWK object.", paramName);

            var kty = ReadString(root, "kty", paramName);
            if (!string.Equals(kty, "EC", StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"{paramName} has kty \"{kty}\"; only EC keys are supported for DPoP (ES256/384/512).",
                    paramName);
            }

            var crv = ReadString(root, "crv", paramName);
            var (namedCurve, alg, hash, width) = crv switch
            {
                "P-256" => (ECCurve.NamedCurves.nistP256, "ES256", HashAlgorithmName.SHA256, 32),
                "P-384" => (ECCurve.NamedCurves.nistP384, "ES384", HashAlgorithmName.SHA384, 48),
                "P-521" => (ECCurve.NamedCurves.nistP521, "ES512", HashAlgorithmName.SHA512, 66),
                _ => throw new ArgumentException(
                    $"{paramName} uses unsupported curve \"{crv}\". Expected P-256, P-384 or P-521.",
                    paramName)
            };

            var x = ReadString(root, "x", paramName);
            var y = ReadString(root, "y", paramName);

            string? d = null;
            if (root.TryGetProperty("d", out var dElement) && dElement.ValueKind == JsonValueKind.String)
                d = dElement.GetString();

            if (requirePrivate && string.IsNullOrEmpty(d))
            {
                throw new ArgumentException(
                    $"{paramName} has no \"d\" member, so it cannot sign. Pass the private JWK.",
                    paramName);
            }

            return new EcJwk(crv, x, y, d, namedCurve, alg, hash, width);
        }

        public bool HasSamePublicPartAs(EcJwk other) =>
            string.Equals(Curve, other.Curve, StringComparison.Ordinal)
            && string.Equals(X, other.X, StringComparison.Ordinal)
            && string.Equals(Y, other.Y, StringComparison.Ordinal);

        public ECDsa CreateSigningKey()
        {
            var parameters = new ECParameters
            {
                Curve = NamedCurve,
                // P-521 coordinates are 66 bytes but often encode to 65 when the leading
                // byte is zero, so every value is left-padded to the curve's fixed width.
                D = Pad(Base64UrlDecode(D!, "d")),
                Q = new ECPoint
                {
                    X = Pad(Base64UrlDecode(X, "x")),
                    Y = Pad(Base64UrlDecode(Y, "y"))
                }
            };

            parameters.Validate();
            return ECDsa.Create(parameters);
        }

        private byte[] Pad(byte[] value)
        {
            if (value.Length == CoordinateBytes)
                return value;

            if (value.Length > CoordinateBytes)
            {
                throw new ArgumentException(
                    $"JWK coordinate is {value.Length} bytes, which is too long for curve {Curve}.");
            }

            var padded = new byte[CoordinateBytes];
            value.CopyTo(padded, CoordinateBytes - value.Length);
            return padded;
        }

        private static string ReadString(JsonElement root, string name, string paramName)
        {
            if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
                throw new ArgumentException($"{paramName} is missing the required JWK member \"{name}\".", paramName);

            var value = element.GetString();
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException($"{paramName} has an empty JWK member \"{name}\".", paramName);

            return value;
        }
    }
}
