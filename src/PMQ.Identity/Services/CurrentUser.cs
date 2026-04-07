using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace PMQ.Identity;

internal sealed class CurrentUser : ICurrentUser
{
    private readonly ClaimsPrincipal? _principal;
    private readonly ClaimsMappingOptions _mapping;

    public CurrentUser(IHttpContextAccessor httpContextAccessor, ClaimsMappingOptions mapping)
    {
        _principal = httpContextAccessor.HttpContext?.User;
        _mapping = mapping;
    }

    public bool IsAuthenticated => _principal?.Identity?.IsAuthenticated ?? false;

    public string? Id => FindClaim(_mapping.UserIdClaimType);

    public string? Email => FindClaim(_mapping.EmailClaimType);

    public IReadOnlyCollection<string> Roles =>
        FindClaims(_mapping.RoleClaimType).ToList().AsReadOnly();

    public string? FindClaim(string claimType) =>
        _principal?.FindFirst(claimType)?.Value;

    public IEnumerable<string> FindClaims(string claimType) =>
        _principal?.FindAll(claimType).Select(c => c.Value) ?? [];
}
