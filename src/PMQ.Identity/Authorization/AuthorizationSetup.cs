using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace PMQ.Identity;

/// <summary>
/// Registers the built-in authorization policies and the dynamic policy provider.
/// </summary>
internal static class AuthorizationSetup
{
    /// <summary>
    /// Configures authorization with the default <see cref="PmqPolicies"/> and an optional additional configuration callback.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureAdditional">An optional callback to add custom authorization policies.</param>
    internal static void Configure(IServiceCollection services, Action<AuthorizationOptions>? configureAdditional = null)
    {
        services.AddAuthorization(options =>
        {
            options.AddPolicy(PmqPolicies.Authenticated, policy =>
                policy.RequireAuthenticatedUser());

            options.AddPolicy(PmqPolicies.AdminOnly, policy =>
                policy.RequireRole("Admin"));

            configureAdditional?.Invoke(options);
        });

        // Dynamic policy provider for PmqPolicies.HasRole()
        services.TryAddSingleton<IAuthorizationPolicyProvider, PmqPolicyProvider>();
    }
}
