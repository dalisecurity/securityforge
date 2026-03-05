# Authenticated Scanning

Most real bugs live behind login walls. Fray supports authenticated scanning across all commands.

## Cookie-Based Auth

```bash
fray recon https://app.example.com --cookie "session=abc123; csrf=xyz"
fray test https://app.example.com -c xss --cookie "session=abc123"
fray scan https://app.example.com --cookie "session=abc123" -w 4
```

## Bearer Token (JWT, API Keys)

```bash
fray test https://api.example.com -c sqli --bearer "eyJhbGciOiJIUzI1NiJ9..."
fray scan https://api.example.com --bearer "your-api-key" -c sqli
```

## Custom Headers

```bash
fray recon https://app.example.com -H "X-API-Key: secret" -H "X-Tenant: acme"
```

## Form Login Flow

```bash
fray test https://app.example.com -c xss \
  --login-flow "https://app.example.com/login,username=admin,password=secret"

# Combine: login + scope + smart mode
fray test https://app.example.com --smart --scope scope.txt \
  --login-flow "https://app.example.com/login,email=user@test.com,password=pass123"
```

## Flag Reference

| Flag | Works With | Description |
|------|-----------|-------------|
| `--cookie` | recon, detect, test, scan | Session cookie string |
| `--bearer` | recon, detect, test, scan | Bearer/JWT token |
| `-H` / `--header` | recon, detect, test, scan | Any custom header (repeatable) |
| `--login-flow` | recon, detect, test | POST form login, auto-capture session cookies |
