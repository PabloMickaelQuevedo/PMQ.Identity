# PMQ.Identity

Provider-agnostic identity module for authentication and authorization in ASP.NET Core applications.  
Supports **External** (OIDC/JWT — e.g. Keycloak, Auth0) and **Local** (self-issued JWT — e.g. ASP.NET Identity) modes.

[![NuGet](https://img.shields.io/nuget/v/PMQ.Identity.svg)](https://www.nuget.org/packages/PMQ.Identity)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.txt)

## Installation

```bash
dotnet add package PMQ.Identity
```

## Quick Start

### 1. Add configuration to `appsettings.json`

Choose **one** of the two modes:

<details>
<summary><b>External Mode (Keycloak example)</b></summary>

```json
{
  "IdentitySettings": {
    "Mode": "External",
    "External": {
      "Authority": "https://keycloak.example.com/realms/my-realm",
      "Audience": "my-api"
    }
  }
}
```

</details>

<details>
<summary><b>Local Mode (self-issued JWT)</b></summary>

```json
{
  "IdentitySettings": {
    "Mode": "Local",
    "Local": {
      "Issuer": "https://my-api.example.com",
      "Audience": "https://my-api.example.com",
      "SecretKey": "a-very-long-secret-key-at-least-32-characters!!",
      "TokenExpirationMinutes": 60
    }
  }
}
```

</details>

### 2. Register services in `Program.cs`

```csharp
builder.Services.AddPmqIdentity(builder.Configuration);

var app = builder.Build();

app.UsePmqIdentity();
```

### 3. Protect endpoints

```csharp
[Authorize(Policy = PmqPolicies.Authenticated)]
[ApiController]
[Route("api/[controller]")]
public class OrdersController : ControllerBase
{
    private readonly ICurrentUser _currentUser;

    public OrdersController(ICurrentUser currentUser)
    {
        _currentUser = currentUser;
    }

    [HttpGet("me")]
    public IActionResult Me()
    {
        return Ok(new
        {
            _currentUser.Id,
            _currentUser.Email,
            _currentUser.Roles
        });
    }

    [Authorize(Policy = PmqPolicies.AdminOnly)]
    [HttpDelete("{id}")]
    public IActionResult Delete(int id) => NoContent();
}
```

---

## External Mode — Keycloak Example

Use this mode when authentication is handled by an external OIDC provider. PMQ.Identity only validates incoming JWTs — it does not manage users or passwords.

### Configuration

```json
{
  "IdentitySettings": {
    "Mode": "External",
    "External": {
      "Authority": "https://keycloak.example.com/realms/my-realm",
      "Audience": "my-api"
    }
  }
}
```

### Registration with Keycloak-specific claims mapping

Keycloak uses `realm_access.roles` instead of the standard `role` claim. You can map it:

```csharp
builder.Services.AddPmqIdentity(builder.Configuration, options =>
{
    options
        .UseExternal()
        .ConfigureClaimsMapping(claims =>
        {
            claims.UserIdClaimType = "sub";
            claims.EmailClaimType = "email";
            claims.RoleClaimType = "realm_roles"; // mapped via Keycloak protocol mapper
        });
});
```

### Advanced: custom token validation and events

```csharp
builder.Services.AddPmqIdentity(builder.Configuration, options =>
{
    options.UseExternal(external =>
    {
        external.RequireHttpsMetadata = true;

        external.ConfigureTokenValidation = tvp =>
        {
            tvp.ValidateIssuer = true;
            tvp.ValidateAudience = true;
        };

        external.ConfigureEvents = events =>
        {
            events.OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Auth failed: {context.Exception.Message}");
                return Task.CompletedTask;
            };
        };
    });
});
```

---

## Local Mode — ASP.NET Identity Example

Use this mode when your API issues its own JWT tokens. You provide the implementations for user storage and password hashing — PMQ.Identity handles token generation, validation, and the authentication pipeline.

### 1. Implement the required interfaces

#### User entity

```csharp
public class AppUser : IdentityUser, IIdentityUser
{
    public string Id => base.Id;
    public string Email => base.Email!;

    public IReadOnlyCollection<Claim> Claims => new List<Claim>
    {
        new(JwtRegisteredClaimNames.Sub, Id),
        new(JwtRegisteredClaimNames.Email, Email),
        new(ClaimTypes.Role, "User")
    };
}
```

#### User store (backed by ASP.NET Identity / EF Core)

```csharp
public class AppUserStore : IUserStore
{
    private readonly UserManager<AppUser> _userManager;

    public AppUserStore(UserManager<AppUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<IIdentityUser?> FindByEmailAsync(string email, CancellationToken ct = default)
    {
        return await _userManager.FindByEmailAsync(email);
    }

    public async Task<IIdentityUser?> FindByIdAsync(string id, CancellationToken ct = default)
    {
        return await _userManager.FindByIdAsync(id);
    }

    public async Task<string?> GetPasswordHashAsync(string userId, CancellationToken ct = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return user?.PasswordHash;
    }
}
```

#### Password hasher (wrapping ASP.NET Identity's hasher)

```csharp
public class AppPasswordHasher : IPasswordHasher
{
    private readonly PasswordHasher<AppUser> _hasher = new();

    public string Hash(string password)
    {
        return _hasher.HashPassword(null!, password);
    }

    public bool Verify(string password, string hash)
    {
        if (string.IsNullOrEmpty(hash)) return false;
        var result = _hasher.VerifyHashedPassword(null!, hash, password);
        return result != PasswordVerificationResult.Failed;
    }
}
```

### 2. Register services

```csharp
// ASP.NET Identity + EF Core setup
builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseNpgsql(builder.Configuration.GetConnectionString("Default")));

builder.Services.AddIdentityCore<AppUser>()
    .AddEntityFrameworkStores<AppDbContext>();

// PMQ.Identity — Local mode
builder.Services.AddPmqIdentity(builder.Configuration, options =>
{
    options.UseLocal();
});

// Register your implementations
builder.Services.AddScoped<IUserStore, AppUserStore>();
builder.Services.AddScoped<IPasswordHasher, AppPasswordHasher>();
```

### 3. Create a login endpoint

```csharp
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthenticationService _authService;

    public AuthController(AuthenticationService authService)
    {
        _authService = authService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken ct)
    {
        var result = await _authService.AuthenticateAsync(request.Email, request.Password, ct);
        if (result is null)
            return Unauthorized();

        return Ok(result); // { accessToken, expiresIn }
    }
}

public record LoginRequest(string Email, string Password);
```

---

## Authorization

PMQ.Identity comes with built-in policies and a dynamic policy provider.

### Built-in policies

| Policy | Description |
| --- | --- |
| `PmqPolicies.Authenticated` | Requires the user to be authenticated |
| `PmqPolicies.AdminOnly` | Requires the "Admin" role |

### Dynamic role policies

```csharp
// Require a specific role — no manual policy registration needed
[Authorize(Policy = "RequireRole:Manager")]
[HttpGet("reports")]
public IActionResult Reports() => Ok();

// Or use the helper method
[Authorize(Policy = PmqPolicies.HasRole("Editor"))]
[HttpPut("{id}")]
public IActionResult Edit(int id) => Ok();
```

### Custom policies

```csharp
builder.Services.AddPmqIdentity(builder.Configuration, options =>
{
    options.ConfigureAuthorization(auth =>
    {
        auth.AddPolicy("MinAge18", policy =>
            policy.RequireClaim("age", "18"));
    });
});
```

---

## ICurrentUser

Inject `ICurrentUser` anywhere to access the authenticated user's information:

```csharp
public class OrderService
{
    private readonly ICurrentUser _currentUser;

    public OrderService(ICurrentUser currentUser)
    {
        _currentUser = currentUser;
    }

    public void DoWork()
    {
        var userId   = _currentUser.Id;
        var email    = _currentUser.Email;
        var roles    = _currentUser.Roles;
        var tenant   = _currentUser.FindClaim("tenant_id");
        var scopes   = _currentUser.FindClaims("scope");
    }
}
```

---

## Claims Mapping

Different providers use different claim types. Configure the mapping to match your provider:

```csharp
builder.Services.AddPmqIdentity(builder.Configuration, options =>
{
    options.ConfigureClaimsMapping(claims =>
    {
        claims.UserIdClaimType = "sub";
        claims.EmailClaimType  = "email";
        claims.RoleClaimType   = "realm_roles";
    });
});
```

---

## API Reference

### Services registered

| Service | Lifetime | Mode | Description |
| --- | --- | --- | --- |
| `ICurrentUser` | Scoped | Both | Access to the authenticated user |
| `ITokenService` | Scoped | Local | JWT token generation |
| `AuthenticationService` | Scoped | Local | Credential validation + token issuance |

### Interfaces to implement (Local mode)

| Interface | Purpose |
| --- | --- |
| `IUserStore` | User lookup by email/id and password hash retrieval |
| `IPasswordHasher` | Password hashing and verification |
| `IIdentityUser` | User entity with id, email, and claims |

---

## License

[MIT](LICENSE.txt)
