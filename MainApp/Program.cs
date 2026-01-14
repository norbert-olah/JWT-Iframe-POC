using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
WebApplication app = builder.Build();

IConfiguration configuration = app.Configuration;

string embeddedOrigin = configuration["Iframe:EmbeddedOrigin"] ?? throw new InvalidOperationException("Missing configuration value: Iframe:EmbeddedOrigin");
string embeddedPath = configuration["Iframe:EmbeddedPath"] ?? throw new InvalidOperationException("Missing configuration value: Iframe:EmbeddedPath");

string issuer = configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:Issuer");
string audience = configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:Audience");
string privateKeyPemPath = configuration["Jwt:PrivateKeyPemPath"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:PrivateKeyPemPath");
string secretClaimName = configuration["Jwt:SecretClaimName"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:SecretClaimName");
string secretClaimValue = configuration["Jwt:SecretClaimValue"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:SecretClaimValue");
int tokenLifetimeMinutes = int.TryParse(configuration["Jwt:TokenLifetimeMinutes"], out int parsedTokenLifetimeMinutes) ? parsedTokenLifetimeMinutes : 5;

app.MapGet("/", () =>
{
    string iframeUrl = $"{embeddedOrigin}{embeddedPath}?Param1=Value1&Param2=Value2&Param3=Value3";

    string html = $$"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>MainApp</title>
  <style>
    body { font-family: sans-serif; margin: 24px; }
    iframe { width: 100%; height: 520px; border: 1px solid #ccc; border-radius: 8px; }
    pre { background: #f7f7f7; padding: 12px; border-radius: 8px; overflow: auto; }
  </style>
</head>
<body>
  <h1>MainApp</h1>
  <p>This page embeds EmbeddedPages via an iframe. JWT is delivered via <code>postMessage</code> (not in URL).</p>

  <iframe id="embeddedFrame" src="{{iframeUrl}}" referrerpolicy="no-referrer"></iframe>

  <h2>Debug</h2>
  <pre id="debug">Waiting for iframe handshake...</pre>

  <script>
    const embeddedOrigin = {{JsonSerializer.Serialize(embeddedOrigin)}};
    const debugEl = document.getElementById('debug');
    const frameEl = document.getElementById('embeddedFrame');

    function log(msg) {
      debugEl.textContent += "\n" + msg;
    }

    window.addEventListener('message', async (event) => {
      if (event.origin !== embeddedOrigin) {
        return;
      }

      if (!event.data || event.data.type !== 'ready') {
        return;
      }

      log('Iframe is ready. Requesting token from /api/token...');
      const response = await fetch('/api/token', { method: 'GET' });
      if (!response.ok) {
        log('Token request failed: ' + response.status);
        return;
      }

      const payload = await response.json();
      if (!payload || !payload.token) {
        log('Token response missing token');
        return;
      }

      log('Sending token to iframe via postMessage...');
      frameEl.contentWindow.postMessage({ type: 'jwt', token: payload.token }, embeddedOrigin);
      log('Done.');
    });
  </script>
</body>
</html>
""";

    return Results.Content(html, "text/html");
});

app.MapGet("/api/token", () =>
{
    string resolvedPrivateKeyPemPath = Path.GetFullPath(Path.Combine(app.Environment.ContentRootPath, privateKeyPemPath));
    if (!File.Exists(resolvedPrivateKeyPemPath))
    {
        return Results.Problem($"Private key PEM not found: {resolvedPrivateKeyPemPath}");
    }

    string privateKeyPem = File.ReadAllText(resolvedPrivateKeyPemPath);
    using RSA rsa = RSA.Create();
    rsa.ImportFromPem(privateKeyPem);

    SecurityKey signingKey = new RsaSecurityKey(rsa);
    SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

    DateTime utcNow = DateTime.UtcNow;
    DateTime expires = utcNow.AddMinutes(tokenLifetimeMinutes);

    Claim[] claims =
    [
        new Claim(secretClaimName, secretClaimValue),
    ];

    JwtSecurityToken token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims,
        notBefore: utcNow,
        expires: expires,
        signingCredentials: signingCredentials);

    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
    string tokenString = handler.WriteToken(token);

    return Results.Ok(new { token = tokenString });
});

app.Run();
