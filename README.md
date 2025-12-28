# Elf.Core.AccessRateLimit

Distributed, Redis-backed access rate limiting for expensive endpoints in ASP.NET Core (.NET 8).

## Overview

Elf.Core.AccessRateLimit protects heavy endpoints (downloads, exports, reports) from abuse by enforcing rate limits across multiple app instances using Redis as the source of truth. It uses atomic Lua scripts for concurrency safety and supports per-endpoint policies, escalation penalties, and simple extension methods.

Key features:
- Distributed enforcement via StackExchange.Redis
- Per-endpoint policy selection (attribute or endpoint mapping)
- Escalating blocks for repeated violations
- Token-bucket algorithm with atomic Redis Lua script
- Optional headers and custom response body
- Structured logging and optional metrics hooks

## Requirements

- .NET 8
- StackExchange.Redis connection (IConnectionMultiplexer)

## Quick start (code)

```csharp
using StackExchange.Redis;
using Elf.Core.AccessRateLimit;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IConnectionMultiplexer>(
    _ => ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")!));

builder.Services.AddElfAccessRateLimit(options =>
{
    options.DefaultPolicyName = "download";
    options.AddPolicy("download", p =>
    {
        p.WithLimit(10, TimeSpan.FromMinutes(1));
        p.WithKeyResolverSpecs("ip", "user");
        p.WithPenalty(penalty =>
        {
            penalty.ViolationWindow = TimeSpan.FromMinutes(10);
            penalty.Penalties = new List<TimeSpan>
            {
                TimeSpan.FromSeconds(10),
                TimeSpan.FromMinutes(1),
                TimeSpan.FromMinutes(5),
                TimeSpan.FromMinutes(30)
            };
        });
    });
});

var app = builder.Build();

app.UseElfAccessRateLimit();

app.MapGet("/download/{id}", () => Results.Ok())
   .RequireAccessRateLimit("download");

app.Run();
```

## Quick start (appsettings.json)

```json
{
  "Elf": {
    "AccessRateLimit": {
      "DefaultPolicyName": "download",
      "RedisKeyPrefix": "elf:accessrl",
      "AddRateLimitHeaders": true,
      "FailOpen": true,
      "Policies": {
        "download": {
          "LimitPerMinute": 10,
          "KeyStrategy": "ip,user",
          "Penalty": {
            "ViolationWindow": "00:10:00",
            "Penalties": [ "00:00:10", "00:01:00", "00:05:00", "00:30:00" ]
          }
        }
      }
    }
  }
}
```

```csharp
builder.Services.AddElfAccessRateLimit(builder.Configuration);
```

## API usage and integration

### Middleware

Register services:

```csharp
builder.Services.AddElfAccessRateLimit(options => { /* policies */ });
```

Add the middleware:

```csharp
app.UseElfAccessRateLimit();
```

Place the middleware after routing (so endpoint metadata is available) and after auth if limits depend on claims.

### Endpoint mapping

```csharp
app.MapGet("/reports/{id}", () => Results.Ok())
   .RequireAccessRateLimit("download");
```

You can override the scope or cost:

```csharp
app.MapGet("/reports/{id}", () => Results.Ok())
   .RequireAccessRateLimit("download", scope: "reports", cost: 5);
```

### Attribute usage (MVC/Web API)

```csharp
[AccessRateLimit("download", Scope = "reports", Cost = 5)]
[HttpGet("/reports/{id}")]
public IActionResult GetReport(string id) => Ok();
```

### Policies (code)

```csharp
options.AddPolicy("export", p =>
{
    p.WithLimit(5, TimeSpan.FromMinutes(1));
    p.WithSharedBucket("exports");
    p.ForAuthenticated(10);
    p.ForAnonymous(3);
    p.WithCost(2);
    p.WithKeyResolverSpecs("ip", "header:X-Api-Key");
});
```

### Policies (config)

```json
"Policies": {
  "export": {
    "Limit": 5,
    "Window": "00:01:00",
    "SharedBucket": "exports",
    "AuthenticatedLimit": 10,
    "AnonymousLimit": 3,
    "Cost": 2,
    "KeyStrategy": "ip,header:X-Api-Key"
  }
}
```

### Key strategies

Built-in specs:
- `ip` (prefers `X-Forwarded-For` / `X-Real-IP`, falls back to `RemoteIpAddress`)
- `user` or `user-id` (ClaimTypes.NameIdentifier)
- `sub`
- `api-key` (X-Api-Key header)
- `client-id` (X-Client-Id header)
- `claim:<type>`
- `header:<name>`

Example:

```csharp
p.WithKeyResolverSpecs("ip", "claim:tenant_id", "header:X-Api-Key");
```

Custom resolver:

```csharp
public sealed class CustomResolver : IRateLimitKeyResolver
{
    public ValueTask<string?> ResolveAsync(HttpContext context, CancellationToken token = default)
        => new ValueTask<string?>(context.Request.Headers["X-Custom"].ToString());
}

p.WithKeyResolver(new CustomResolver());
```

### Escalating penalties

Use `Penalty` to increase block duration for repeated violations:

```csharp
p.WithPenalty(penalty =>
{
    penalty.ViolationWindow = TimeSpan.FromMinutes(10);
    penalty.Penalties = new List<TimeSpan>
    {
        TimeSpan.FromSeconds(10),
        TimeSpan.FromMinutes(1),
        TimeSpan.FromMinutes(5),
        TimeSpan.FromMinutes(30)
    };
});
```

### Headers and responses

When limited, the middleware returns HTTP 429 with:
- `Retry-After`
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

Customize the response:

```csharp
options.Response.ContentType = "application/json";
options.Response.Body = "{\"error\":\"rate_limited\"}";
options.Response.OnRejected = (ctx, decision) =>
{
    ctx.Response.ContentType = "application/json";
    return ctx.Response.WriteAsync("{\"error\":\"rate_limited\"}");
};
```

### Metrics hooks

Implement and register a metrics handler:

```csharp
public sealed class RateLimitMetrics : IAccessRateLimitMetrics
{
    public void OnAllowed(AccessRateLimitDecision decision) { }
    public void OnLimited(AccessRateLimitDecision decision) { }
    public void OnBlocked(AccessRateLimitDecision decision) { }
}

builder.Services.AddSingleton<IAccessRateLimitMetrics, RateLimitMetrics>();
```

### Whitelisting

```csharp
options.ExemptWhen = ctx =>
    ctx.User.IsInRole("Admin") ||
    ctx.Connection.RemoteIpAddress?.ToString() == "10.0.0.1";
```

## Notes

- Redis is the source of truth; optional local caching is not required.
- `FailOpen = true` allows requests if Redis is unavailable (logged as error).
- Use `SharedBucket` or per-request `scope` to share a limit across multiple endpoints.
- `Cost` lets heavy endpoints consume more tokens per request.

## Samples

The console app `Elf.Test.Samples` spins up a local in-process WebApplication and exercises the limiter.

```bash
dotnet run --project Elf.Test.Samples -- --redis localhost:6379 --sample all
```

Samples available: `all`, `basic`, `keys`, `escalation`.

## Folder layout

- Configuration: options and validation
- Policies: policy models and provider
- Keys: key resolvers and key utilities
- Store: Redis Lua store
- Middleware: rate limit pipeline
- Extensions: service/middleware/endpoint registration
- Metadata: endpoint metadata + attribute
- Metrics: metrics contracts
- Models: decision model

## Design

The limiter runs in middleware, resolves a policy per endpoint, builds a stable caller key, and evaluates a token bucket in Redis with an atomic Lua script. The Redis result drives allow/deny, headers, logging, and escalation penalties.

Key points that enforce the limit:
- Policy resolution chooses the endpoint policy or the configured default.
- Key resolution uses policy resolvers (IP, header, claim, composite) and hashes the result before Redis.
- Bucket scope defaults to the route pattern, but can be overridden to share limits.
- Redis Lua script checks blocks, refills tokens, applies cost, and increments violations safely.
- Escalation penalties set a block key with growing TTLs for repeated violations.
- Responses return 429 with Retry-After and optional rate limit headers.
