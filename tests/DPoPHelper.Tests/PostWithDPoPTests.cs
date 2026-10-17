using System.Net;
using System.Text;
using Xunit;

namespace DPoPHelper.Tests;

/// <summary>
/// Drives PostWithDPoP against a real loopback HTTP listener. The whole point of the
/// action is reading a response header, so a mocked handler would test nothing.
/// </summary>
public class PostWithDPoPTests : IDisposable
{
    private readonly IDPoPHelper _sut = new DPoPHelper();
    private readonly HttpListener _listener;
    private readonly string _prefix;

    // Captured from the last received request so assertions can inspect what was sent.
    private string? _lastDPoPHeader;
    private string? _lastContentType;
    private string? _lastBody;
    private string? _lastMethod;
    private string? _lastAuthorizationHeader;

    public PostWithDPoPTests()
    {
        var port = GetFreePort();
        _prefix = $"http://127.0.0.1:{port}/";
        _listener = new HttpListener();
        _listener.Prefixes.Add(_prefix);
        _listener.Start();
    }

    public void Dispose()
    {
        if (_listener.IsListening) _listener.Stop();
        _listener.Close();
        GC.SuppressFinalize(this);
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>Serves exactly one request with the given status, body and headers.</summary>
    private Task ServeOnce(int status, string body, params (string Name, string Value)[] headers) =>
        Task.Run(() =>
        {
            var ctx = _listener.GetContext();

            _lastMethod = ctx.Request.HttpMethod;
            _lastDPoPHeader = ctx.Request.Headers["DPoP"];
            _lastAuthorizationHeader = ctx.Request.Headers["Authorization"];
            _lastContentType = ctx.Request.ContentType;
            using (var sr = new StreamReader(ctx.Request.InputStream, Encoding.UTF8))
                _lastBody = sr.ReadToEnd();

            ctx.Response.StatusCode = status;
            foreach (var (name, value) in headers)
                ctx.Response.Headers.Add(name, value);

            var bytes = Encoding.UTF8.GetBytes(body);
            ctx.Response.ContentLength64 = bytes.Length;
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            ctx.Response.OutputStream.Close();
        });

    [Fact]
    public async Task Returns_status_body_and_empty_nonce_on_success()
    {
        var server = ServeOnce(200, """{"access_token":"at","token_type":"DPoP"}""");

        _sut.PostWithDPoP(_prefix, "grant_type=authorization_code", "proof.jwt",
            out var status, out var responseBody, out var nonce);

        await server;

        Assert.Equal(200, status);
        Assert.Contains("access_token", responseBody, StringComparison.Ordinal);
        Assert.Equal(string.Empty, nonce);
    }

    [Fact]
    public async Task Extracts_DPoP_Nonce_from_a_400_use_dpop_nonce_response()
    {
        // The exact handshake the retry depends on.
        var server = ServeOnce(400, """{"error":"use_dpop_nonce"}""",
            ("DPoP-Nonce", "eyJ7S_zG.eyJbYu3xw"));

        _sut.PostWithDPoP(_prefix, "grant_type=authorization_code", "proof.jwt",
            out var status, out var responseBody, out var nonce);

        await server;

        Assert.Equal(400, status);
        Assert.Contains("use_dpop_nonce", responseBody, StringComparison.Ordinal);
        Assert.Equal("eyJ7S_zG.eyJbYu3xw", nonce);
    }

    [Theory]
    [InlineData("dpop-nonce")]
    [InlineData("DPOP-NONCE")]
    [InlineData("DPoP-Nonce")]
    public async Task Nonce_lookup_is_case_insensitive(string headerName)
    {
        var server = ServeOnce(400, "{}", (headerName, "abc123"));

        _sut.PostWithDPoP(_prefix, "x=1", "proof.jwt",
            out _, out _, out var nonce);

        await server;

        Assert.Equal("abc123", nonce);
    }

    [Fact]
    public async Task Does_not_throw_on_non_success_status()
    {
        // A 400 is part of the protocol, not a failure - the caller must branch on it.
        var server = ServeOnce(401, """{"error":"invalid_dpop_proof"}""");

        var ex = Record.Exception(() =>
            _sut.PostWithDPoP(_prefix, "x=1", "proof.jwt", out var s, out _, out _));

        await server;
        Assert.Null(ex);
    }

    [Fact]
    public async Task Sends_the_proof_as_the_DPoP_header_with_the_right_method_and_body()
    {
        var server = ServeOnce(200, "{}");

        _sut.PostWithDPoP(_prefix, "grant_type=authorization_code&code=xyz", "the.proof.jwt",
            out _, out _, out _);

        await server;

        Assert.Equal("POST", _lastMethod);
        Assert.Equal("the.proof.jwt", _lastDPoPHeader);
        Assert.Equal("grant_type=authorization_code&code=xyz", _lastBody);
    }

    [Fact]
    public async Task Sends_form_urlencoded_without_a_charset_suffix_by_default()
    {
        var server = ServeOnce(200, "{}");

        _sut.PostWithDPoP(_prefix, "x=1", "proof.jwt", out _, out _, out _);

        await server;

        // Strict token endpoints reject "...; charset=utf-8" on form posts.
        Assert.Equal("application/x-www-form-urlencoded", _lastContentType);
    }

    [Fact]
    public async Task Honours_an_overridden_content_type()
    {
        var server = ServeOnce(200, "{}");

        _sut.PostWithDPoP(_prefix, "{}", "proof.jwt", out _, out _, out _,
            contentType: "application/json");

        await server;

        Assert.Equal("application/json", _lastContentType);
    }

    [Fact]
    public void Times_out_rather_than_hanging()
    {
        // Listener is up but never answers.
        var ex = Record.Exception(() =>
            _sut.PostWithDPoP(_prefix, "x=1", "proof.jwt",
                out _, out _, out _, timeoutSeconds: 1));

        Assert.NotNull(ex);
        Assert.True(
            ex is TaskCanceledException or OperationCanceledException or HttpRequestException,
            $"Expected a cancellation/transport exception, got {ex.GetType().Name}: {ex.Message}");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-absolute-url")]
    // A bare path parses as an absolute file:// URI on Unix but not on Windows, so an
    // is-absolute check alone behaves differently per platform.
    [InlineData("/relative/path")]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://example.test/token")]
    public void Rejects_a_bad_url(string url)
    {
        Assert.Throws<ArgumentException>(() =>
            _sut.PostWithDPoP(url, "x=1", "proof.jwt", out _, out _, out _));
    }

    [Fact]
    public void Rejects_a_missing_proof()
    {
        Assert.Throws<ArgumentException>(() =>
            _sut.PostWithDPoP("https://example.test/token", "x=1", "", out _, out _, out _));
    }

    [Fact]
    public void Rejects_a_timeout_above_the_maximum()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            _sut.PostWithDPoP("https://example.test/token", "x=1", "proof.jwt",
                out _, out _, out _, timeoutSeconds: 301));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task Treats_a_non_positive_timeout_as_unset_rather_than_failing(int seconds)
    {
        // ODC sends 0 for an Integer input left unset at the call site rather than the
        // action's declared default, so 0 must fall back, not throw.
        var server = ServeOnce(200, "{}");

        _sut.PostWithDPoP(_prefix, "x=1", "proof.jwt",
            out var status, out _, out _, timeoutSeconds: seconds);

        await server;
        Assert.Equal(200, status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Treats_an_empty_content_type_as_unset(string contentType)
    {
        var server = ServeOnce(200, "{}");

        _sut.PostWithDPoP(_prefix, "x=1", "proof.jwt",
            out _, out _, out _, contentType: contentType);

        await server;
        Assert.Equal("application/x-www-form-urlencoded", _lastContentType);
    }

    // --- GetWithDPoP -------------------------------------------------------------

    [Fact]
    public async Task Get_sends_authorization_dpop_scheme_and_the_proof()
    {
        var server = ServeOnce(200, "encrypted.jwe.payload");

        _sut.GetWithDPoP(_prefix, "the-access-token", "the.proof.jwt",
            out var status, out var body, out var nonce);

        await server;

        Assert.Equal("GET", _lastMethod);
        Assert.Equal("DPoP the-access-token", _lastAuthorizationHeader);
        Assert.Equal("the.proof.jwt", _lastDPoPHeader);
        Assert.Equal(200, status);
        Assert.Equal("encrypted.jwe.payload", body);
        Assert.Equal(string.Empty, nonce);
    }

    [Fact]
    public async Task Get_never_sends_bearer()
    {
        var server = ServeOnce(200, "{}");

        _sut.GetWithDPoP(_prefix, "tok", "proof.jwt", out _, out _, out _);

        await server;
        Assert.DoesNotContain("Bearer", _lastAuthorizationHeader!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Get_extracts_the_nonce_from_a_401_challenge()
    {
        // UserInfo answers 401 with use_dpop_nonce, not 400.
        var server = ServeOnce(401, """{"error":"use_dpop_nonce"}""",
            ("DPoP-Nonce", "userinfo-nonce-1"));

        _sut.GetWithDPoP(_prefix, "tok", "proof.jwt",
            out var status, out _, out var nonce);

        await server;

        Assert.Equal(401, status);
        Assert.Equal("userinfo-nonce-1", nonce);
    }

    [Fact]
    public void Get_rejects_a_missing_access_token()
    {
        Assert.Throws<ArgumentException>(() =>
            _sut.GetWithDPoP("https://example.test/userinfo", "", "proof.jwt",
                out _, out _, out _));
    }

    [Fact]
    public void Get_rejects_a_bad_url()
    {
        Assert.Throws<ArgumentException>(() =>
            _sut.GetWithDPoP("/relative", "tok", "proof.jwt", out _, out _, out _));
    }
}
