# JWT + iframe POC (MainApp → EmbeddedPages)

A minimal ASP.NET Core 8 proof-of-concept showing how to pass a JWT from a parent web app (`MainApp`) to an embedded iframe (`EmbeddedPages`) **without exposing the token in the URL**. Uses industry-standard `window.postMessage` for cross-origin handoff and server-side RS256 validation.

## Architecture

```
MainApp (https://localhost:7053)
│  GET /  → HTML page with iframe
│  GET /api/token → RS256 JWT (signed with private PEM)
│  postMessage(token) → iframe
│
└─iframe→ EmbeddedPages (https://localhost:7129/embedded?Param1=Value1&Param2=Value2&Param3=Value3)
   │  postMessage('ready') → parent
   │  postMessage('jwt', token) ← parent
   │  POST /api/validate (Authorization: Bearer <token>)
   │  → validates RS256 signature + SecretParam claim
```

## Quick start

### 1) Build

```bash
dotnet build JwtIframePoc.sln
```

### 2) Run both apps

**Recommended (Windsurf)**  
- Open **Tasks: Run Task** → `run: Both apps (watch, https)`

**Manual**

```bash
# Terminal 1
dotnet watch run --project ./EmbeddedPages/EmbeddedPages.csproj --launch-profile https

# Terminal 2
dotnet watch run --project ./MainApp/MainApp.csproj --launch-profile https
```

### 3) Browse

Open `https://localhost:7053/` in a browser.

**Expected flow**

- MainApp page loads with an iframe pointing to `EmbeddedPages/embedded?Param1=Value1&Param2=Value2&Param3=Value3`
- Iframe sends `{type:'ready'}` to the parent via `postMessage`
- MainApp calls `/api/token` to get a short-lived RS256 JWT
- MainApp sends `{type:'jwt', token:'...'}` to the iframe via `postMessage`
- Iframe calls `POST /api/validate` with `Authorization: Bearer <token>`
- Iframe displays `HTTP 200` and JSON including `valid:true` and `secretClaim:"SecretValue"`

## Configuration

| Project | File | Key settings |
|---------|------|--------------|
| MainApp | `appsettings.json` | `Iframe:EmbeddedOrigin`, `Jwt:PrivateKeyPemPath` |
| EmbeddedPages | `appsettings.json` | `Security:AllowedParentOrigin`, `Jwt:PublicKeyPemPath` |

PEM files (RSA-256) are expected at:
- `Keys/mainapp-private.pem` (used by MainApp to sign)
- `Keys/embeddedpages-public.pem` (used by EmbeddedPages to verify)

## Security notes

- **No JWT in URL** – token is delivered via `postMessage` and then validated server-side.
- `EmbeddedPages` sets `Content-Security-Policy: frame-ancestors <MainApp origin>` to restrict framing.
- Tokens are short-lived (default 5 minutes) and include a required claim (`SecretParam`).

## Windsurf / VS Code

- `.vscode/launch.json` provides a compound launch profile.
- **Debugging is not supported in Windsurf** (VS Code fork license limitation).  
  Use tasks (`dotnet watch`), logs, and browser devtools, or debug in Visual Studio / Rider if you need breakpoints.

## Files of interest

- `MainApp/Program.cs` – MainApp endpoints and HTML with iframe + postMessage JS
- `EmbeddedPages/Program.cs` – EmbeddedPages page, CSP, and JWT validation endpoint
- `.vscode/tasks.json` – Run tasks for both apps (dotnet watch)
- `Keys/` – RSA-256 PEM key files (not in repo; you must add them)

## Troubleshooting

- **Build fails with file locked** – stop the running apps first (`Ctrl+C` or stop task).
- **HTTPS warnings** – trust the dev cert once: `dotnet dev-certs https --trust`.
- **Iframe 404** – ensure you opened `https://localhost:7053/` (not http) and that both apps are running.
- **postMessage not received** – check browser console for origin mismatches; verify CSP `frame-ancestors` matches your MainApp origin.
