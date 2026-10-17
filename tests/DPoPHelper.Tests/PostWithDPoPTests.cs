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

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(301)]
    public void Rejects_an_out_of_range_timeout(int seconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            _sut.PostWithDPoP("https://example.test/token", "x=1", "proof.jwt",
                out _, out _, out _, timeoutSeconds: seconds));
    }
}
