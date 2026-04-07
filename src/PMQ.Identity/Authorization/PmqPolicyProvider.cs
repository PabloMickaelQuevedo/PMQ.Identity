using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace PMQ.Identity;

/// <summary>
/// Dynamic authorization policy provider that resolves <c>RequireRole:{role}</c> policies at runtime,
/// falling back to the default provider for all other policy names.
/// </summary>
internal sealed class PmqPolicyProvider : IAuthorizationPolicyProvider
{
    private const string RolePrefix = "RequireRole:";
    private readonly DefaultAuthorizationPolicyProvider _fallback;

    /// <summary>
    /// Initializes a new instance of <see cref="PmqPolicyProvider"/>.
    /// </summary>
    /// <param name="options">The configured authorization options.</param>
    public PmqPolicyProvider(IOptions<AuthorizationOptions> options)
    {
        _fallback = new DefaultAuthorizationPolicyProvider(options);
    }

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith(RolePrefix, StringComparison.OrdinalIgnoreCase))
        {
            var role = policyName[RolePrefix.Length..];
            var policy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .RequireRole(role)
                .Build();
            return Task.FromResult<AuthorizationPolicy?>(policy);
        }

        return _fallback.GetPolicyAsync(policyName);
    }

    /// <inheritdoc />
    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() =>
        _fallback.GetDefaultPolicyAsync();

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() =>
        _fallback.GetFallbackPolicyAsync();
}
