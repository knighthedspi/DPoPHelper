using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace DPoPHelper.Tests;

public class CreateDPoPProofTests
{
    private readonly IDPoPHelper _sut = new DPoPHelper();

    private const string Htu = "https://stg-id.singpass.gov.sg/par";
    private const string Jti = "9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f";
    private const long Iat = 1_760_000_000L;

    /// <summary>Generates a throwaway key and returns (privateJwk, publicJwk).</summary>
    private static (string Private, string Public) NewKeyPair(string curveName = "P-256")
    {
        var curve = curveName switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentOutOfRangeException(nameof(curveName))
        };

        using var ecdsa = ECDsa.Create(curve);
        var p = ecdsa.ExportParameters(includePrivateParameters: true);

        static string B64(byte[] b) =>
            Convert.ToBase64String(b).Replace('+', '-').Replace('/', '_').TrimEnd('=');

        var x = B64(p.Q.X!);
        var y = B64(p.Q.Y!);

        var priv = $$"""{"kty":"EC","crv":"{{curveName}}","x":"{{x}}","y":"{{y}}","d":"{{B64(p.D!)}}"}""";
        var pub = $$"""{"kty":"EC","crv":"{{curveName}}","x":"{{x}}","y":"{{y}}"}""";
        return (priv, pub);
    }

    /// <summary>base64url -> bytes, computing the padding rather than assuming it.</summary>
    private static byte[] Dec(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(s);
    }

    /// <summary>base64url segment -> decoded UTF-8 text.</summary>
    private static string DecText(string segment) => Encoding.UTF8.GetString(Dec(segment));

    private static (JsonElement Header, JsonElement Payload, byte[] Signature, string SigningInput) Decode(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        return (
            JsonDocument.Parse(Dec(parts[0])).RootElement.Clone(),
            JsonDocument.Parse(Dec(parts[1])).RootElement.Clone(),
            Dec(parts[2]),
            parts[0] + "." + parts[1]);
    }

    // --- Singpass mandatory header requirements ---------------------------------

    [Fact]
    public void Header_typ_is_exactly_dpop_jwt()
    {
        var (priv, pub) = NewKeyPair();
        var (header, _, _, _) = Decode(_sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, ""));

        Assert.Equal("dpop+jwt", header.GetProperty("typ").GetString());
    }

    [Theory]
    [InlineData("P-256", "ES256")]
    [InlineData("P-384", "ES384")]
    [InlineData("P-521", "ES512")]
    public void Header_alg_follows_the_curve(string curve, string expectedAlg)
    {
        var (priv, pub) = NewKeyPair(curve);
        var (header, _, _, _) = Decode(_sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, ""));

        Assert.Equal(expectedAlg, header.GetProperty("alg").GetString());
    }

    [Fact]
    public void Header_embeds_the_public_jwk()
    {
        var (priv, pub) = NewKeyPair();
        var expected = JsonDocument.Parse(pub).RootElement;

        var (header, _, _, _) = Decode(_sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, ""));
        var jwk = header.GetProperty("jwk");

        Assert.Equal("EC", jwk.GetProperty("kty").GetString());
        Assert.Equal(expected.GetProperty("crv").GetString(), jwk.GetProperty("crv").GetString());
        Assert.Equal(expected.GetProperty("x").GetString(), jwk.GetProperty("x").GetString());
        Assert.Equal(expected.GetProperty("y").GetString(), jwk.GetProperty("y").GetString());
    }

    [Fact]
    public void Header_jwk_never_contains_the_private_exponent()
    {
        var (priv, pub) = NewKeyPair();

        // Deliberately pass the PRIVATE jwk in the public slot - the worst-case
        // caller mistake. The proof must still not leak "d".
        var jwt = _sut.CreateDPoPProof(priv, priv, "POST", Htu, Jti, Iat, "");
        var (header, _, _, _) = Decode(jwt);

        Assert.False(header.GetProperty("jwk").TryGetProperty("d", out _));
        Assert.DoesNotContain("\"d\"", DecText(jwt.Split('.')[0]), StringComparison.Ordinal);

        // And the correct usage produces the identical header.
        Assert.Equal(jwt.Split('.')[0], _sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, "").Split('.')[0]);
    }

    [Fact]
    public void Header_jwk_members_are_in_rfc7638_order()
    {
        var (priv, pub) = NewKeyPair();
        var jwt = _sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, "");

        var headerJson = DecText(jwt.Split('.')[0]);

        var jwkStart = headerJson.IndexOf("\"jwk\"", StringComparison.Ordinal);
        var jwkJson = headerJson[jwkStart..];

        // RFC 7638 requires lexicographic order: crv, kty, x, y.
        Assert.True(jwkJson.IndexOf("\"crv\"", StringComparison.Ordinal)
                    < jwkJson.IndexOf("\"kty\"", StringComparison.Ordinal));
        Assert.True(jwkJson.IndexOf("\"kty\"", StringComparison.Ordinal)
                    < jwkJson.IndexOf("\"x\"", StringComparison.Ordinal));
        Assert.True(jwkJson.IndexOf("\"x\"", StringComparison.Ordinal)
                    < jwkJson.IndexOf("\"y\"", StringComparison.Ordinal));
    }

    // --- Payload claims ----------------------------------------------------------

    [Fact]
    public void Payload_iat_is_an_unquoted_number()
    {
        var (priv, pub) = NewKeyPair();
        var jwt = _sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, "");
        var (_, payload, _, _) = Decode(jwt);

        Assert.Equal(JsonValueKind.Number, payload.GetProperty("iat").ValueKind);
        Assert.Equal(Iat, payload.GetProperty("iat").GetInt64());

        var payloadJson = DecText(jwt.Split('.')[1]);
        Assert.Contains("\"iat\":1760000000", payloadJson, StringComparison.Ordinal);
        Assert.DoesNotContain("\"iat\":\"", payloadJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Payload_has_exactly_one_iat_and_one_jti()
    {
        var (priv, pub) = NewKeyPair();
        var jwt = _sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, "");

        var payloadJson = DecText(jwt.Split('.')[1]);

        Assert.Equal(1, Occurrences(payloadJson, "\"iat\""));
        Assert.Equal(1, Occurrences(payloadJson, "\"jti\""));

        static int Occurrences(string haystack, string needle)
        {
            int count = 0, i = 0;
            while ((i = haystack.IndexOf(needle, i, StringComparison.Ordinal)) >= 0) { count++; i += needle.Length; }
            return count;
        }
    }

    [Fact]
    public void Payload_omits_ath_when_empty_and_includes_it_otherwise()
    {
        var (priv, pub) = NewKeyPair();

        var (_, withoutAth, _, _) = Decode(_sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, ""));
        Assert.False(withoutAth.TryGetProperty("ath", out _));

        var (_, withAth, _, _) = Decode(_sut.CreateDPoPProof(priv, pub, "GET", Htu, Jti, Iat, "abc123"));
        Assert.Equal("abc123", withAth.GetProperty("ath").GetString());
    }

    [Theory]
    [InlineData("https://host/userinfo?x=1", "https://host/userinfo")]
    [InlineData("https://host/userinfo#frag", "https://host/userinfo")]
    [InlineData("https://host/userinfo?x=1#frag", "https://host/userinfo")]
    [InlineData("https://host/userinfo", "https://host/userinfo")]
    public void Payload_htu_strips_query_and_fragment(string input, string expected)
    {
        var (priv, pub) = NewKeyPair();
        var (_, payload, _, _) = Decode(_sut.CreateDPoPProof(priv, pub, "GET", input, Jti, Iat, ""));

        Assert.Equal(expected, payload.GetProperty("htu").GetString());
    }

    [Fact]
    public void Payload_htm_is_uppercased()
    {
        var (priv, pub) = NewKeyPair();
        var (_, payload, _, _) = Decode(_sut.CreateDPoPProof(priv, pub, "post", Htu, Jti, Iat, ""));

        Assert.Equal("POST", payload.GetProperty("htm").GetString());
    }

    // --- Signature ---------------------------------------------------------------

    [Theory]
    [InlineData("P-256")]
    [InlineData("P-384")]
    [InlineData("P-521")]
    public void Signature_verifies_against_the_embedded_jwk(string curveName)
    {
        var (priv, pub) = NewKeyPair(curveName);
        var jwt = _sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, "");
        var (header, _, signature, signingInput) = Decode(jwt);

        // Rebuild the verifier purely from what the proof carries, exactly as the
        // authorization server would.
        var jwk = header.GetProperty("jwk");

        var curve = curveName switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521
        };

        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = Dec(jwk.GetProperty("x").GetString()!),
                Y = Dec(jwk.GetProperty("y").GetString()!)
            }
        });

        var hash = header.GetProperty("alg").GetString() switch
        {
            "ES256" => HashAlgorithmName.SHA256,
            "ES384" => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512
        };

        Assert.True(verifier.VerifyData(Encoding.ASCII.GetBytes(signingInput), signature, hash));
    }

    [Fact]
    public void Signature_is_p1363_fixed_width_not_der()
    {
        var (priv, pub) = NewKeyPair();
        var (_, _, signature, _) = Decode(_sut.CreateDPoPProof(priv, pub, "POST", Htu, Jti, Iat, ""));

        // ES256 is r||s at 32 bytes each. A DER-encoded signature would start with 0x30
        // and vary in length - that is the classic JWS signing bug.
        Assert.Equal(64, signature.Length);
        Assert.NotEqual(0x30, signature[0]);
    }

    [Fact]
    public void Each_call_is_independent_so_proofs_are_single_use()
    {
        var (priv, pub) = NewKeyPair();

        var first = _sut.CreateDPoPProof(priv, pub, "POST", Htu, Guid.NewGuid().ToString(), Iat, "");
        var second = _sut.CreateDPoPProof(priv, pub, "POST", Htu, Guid.NewGuid().ToString(), Iat, "");

        Assert.NotEqual(first, second);
        // Same session key, so the header (and therefore the jkt binding) is stable.
        Assert.Equal(first.Split('.')[0], second.Split('.')[0]);
    }

    // --- Input validation --------------------------------------------------------

    [Fact]
    public void Rejects_mismatched_key_pair()
    {
        var (priv, _) = NewKeyPair();
        var (_, otherPub) = NewKeyPair();

        var ex = Assert.Throws<ArgumentException>(() =>
            _sut.CreateDPoPProof(priv, otherPub, "POST", Htu, Jti, Iat, ""));

        Assert.Contains("does not match", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_public_key_in_the_signing_slot()
    {
        var (_, pub) = NewKeyPair();

        var ex = Assert.Throws<ArgumentException>(() =>
            _sut.CreateDPoPProof(pub, pub, "POST", Htu, Jti, Iat, ""));

        Assert.Contains("\"d\"", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json")]
    [InlineData("{\"kty\":\"RSA\",\"n\":\"x\",\"e\":\"AQAB\"}")]
    [InlineData("{\"kty\":\"EC\",\"crv\":\"P-224\",\"x\":\"a\",\"y\":\"b\",\"d\":\"c\"}")]
    [InlineData("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"a\"}")]
    public void Rejects_malformed_private_jwk(string badJwk)
    {
        var (_, pub) = NewKeyPair();

        Assert.Throws<ArgumentException>(() =>
            _sut.CreateDPoPProof(badJwk, pub, "POST", Htu, Jti, Iat, ""));
    }

    [Theory]
    [InlineData(null, "POST", "https://h/p", "jti")]
    [InlineData("", "POST", "https://h/p", "jti")]
    [InlineData("priv", "", "https://h/p", "jti")]
    [InlineData("priv", "POST", "", "jti")]
    [InlineData("priv", "POST", "https://h/p", "")]
    public void Rejects_missing_required_inputs(string? priv, string htm, string htu, string jti)
    {
        var (realPriv, pub) = NewKeyPair();
        var p = priv == "priv" ? realPriv : priv!;

        Assert.ThrowsAny<ArgumentException>(() =>
            _sut.CreateDPoPProof(p, pub, htm, htu, jti, Iat, ""));
    }
}
