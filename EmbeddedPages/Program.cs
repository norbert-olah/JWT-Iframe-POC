using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
WebApplication app = builder.Build();

IConfiguration configuration = app.Configuration;

string allowedParentOrigin = configuration["Security:AllowedParentOrigin"] ?? throw new InvalidOperationException("Missing configuration value: Security:AllowedParentOrigin");

string issuer = configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:Issuer");
string audience = configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:Audience");
string publicKeyPemPath = configuration["Jwt:PublicKeyPemPath"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:PublicKeyPemPath");
string secretClaimName = configuration["Jwt:SecretClaimName"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:SecretClaimName");
string secretClaimValue = configuration["Jwt:SecretClaimValue"] ?? throw new InvalidOperationException("Missing configuration value: Jwt:SecretClaimValue");

app.Use(async (context, next) =>
{
    context.Response.Headers["Content-Security-Policy"] = $"frame-ancestors {allowedParentOrigin}";
    await next(context);
});

app.MapGet("/", () => Results.Redirect("/embedded"));

app.MapGet("/embedded", () =>
{
    string html = $$"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EmbeddedPages</title>
  <style>
    body { font-family: sans-serif; margin: 16px; }
    .box { border: 1px solid #ccc; border-radius: 8px; padding: 12px; margin-bottom: 12px; }
    pre { background: #f7f7f7; padding: 12px; border-radius: 8px; overflow: auto; }
  </style>
</head>
<body>
  <h1>EmbeddedPages</h1>
  <div class="box">
    <div><strong>Query Params</strong></div>
    <div id="params">Loading...</div>
  </div>
  <div class="box">
    <div><strong>JWT Validation</strong></div>
    <pre id="result">Waiting for token via postMessage...</pre>
  </div>

  <script>
    const allowedParentOrigin = {{JsonSerializer.Serialize(allowedParentOrigin)}};
    const paramsEl = document.getElementById('params');
    const resultEl = document.getElementById('result');

    function showParams() {
      const sp = new URLSearchParams(window.location.search);
      const p1 = sp.get('Param1');
      const p2 = sp.get('Param2');
      const p3 = sp.get('Param3');
      paramsEl.textContent = `Param1=${p1} | Param2=${p2} | Param3=${p3}`;
    }

    async function validateToken(token) {
      resultEl.textContent = 'Validating token server-side...';
      const response = await fetch('/api/validate', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token
        }
      });

      const text = await response.text();
      resultEl.textContent = `HTTP ${response.status}\n${text}`;
    }

    window.addEventListener('message', async (event) => {
      if (event.origin !== allowedParentOrigin) {
        return;
      }

      if (!event.data || event.data.type !== 'jwt' || !event.data.token) {
        return;
      }

      await validateToken(event.data.token);
    });

    showParams();
    window.parent.postMessage({ type: 'ready' }, allowedParentOrigin);
  </script>
</body>
</html>
""";

    return Results.Content(html, "text/html");
});

app.MapPost("/api/validate", (HttpRequest request) =>
{
    string? authorization = request.Headers.Authorization;
    if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Unauthorized();
    }

    string tokenString = authorization["Bearer ".Length..].Trim();
    if (string.IsNullOrWhiteSpace(tokenString))
    {
        return Results.Unauthorized();
    }

    string resolvedPublicKeyPemPath = Path.GetFullPath(Path.Combine(app.Environment.ContentRootPath, publicKeyPemPath));
    if (!File.Exists(resolvedPublicKeyPemPath))
    {
        return Results.Problem($"Public key PEM not found: {resolvedPublicKeyPemPath}");
    }

    string publicKeyPem = File.ReadAllText(resolvedPublicKeyPemPath);
    using RSA rsa = RSA.Create();
    rsa.ImportFromPem(publicKeyPem);

    TokenValidationParameters validationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new RsaSecurityKey(rsa),
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30),
    };

    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
    try
    {
        System.Security.Claims.ClaimsPrincipal principal = handler.ValidateToken(tokenString, validationParameters, out SecurityToken validatedToken);

        string? actualSecret = principal.FindFirst(secretClaimName)?.Value;
        if (!string.Equals(actualSecret, secretClaimValue, StringComparison.Ordinal))
        {
            return Results.Unauthorized();
        }

        return Results.Ok(new
        {
            valid = true,
            issuer,
            audience,
            expiresUtc = validatedToken.ValidTo,
            secretClaim = actualSecret,
        });
    }
    catch (Exception)
    {
        return Results.Unauthorized();
    }
});

app.Run();
