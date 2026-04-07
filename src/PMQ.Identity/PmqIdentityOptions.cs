using Microsoft.AspNetCore.Authorization;

namespace PMQ.Identity;

/// <summary>
/// Fluent options for configuring PMQ.Identity during service registration.
/// </summary>
public sealed class PmqIdentityOptions
{
    internal IdentityMode? ModeOverride { get; private set; }
    internal Action<ExternalSettings>? ExternalConfigure { get; private set; }
    internal Action<LocalSettings>? LocalConfigure { get; private set; }
    internal Action<AuthorizationOptions>? AuthorizationConfigure { get; private set; }
    internal Action<ClaimsMappingOptions>? ClaimsMappingConfigure { get; private set; }

    /// <summary>
    /// Configures PMQ.Identity to use an external OIDC/JWT identity provider.
    /// </summary>
    /// <param name="configure">An optional callback to customize <see cref="ExternalSettings"/>.</param>
    /// <returns>The current <see cref="PmqIdentityOptions"/> instance for chaining.</returns>
    public PmqIdentityOptions UseExternal(Action<ExternalSettings>? configure = null)
    {
        ModeOverride = IdentityMode.External;
        ExternalConfigure = configure;
        return this;
    }

    /// <summary>
    /// Configures PMQ.Identity to use locally-issued JWT tokens.
    /// </summary>
    /// <param name="configure">An optional callback to customize <see cref="LocalSettings"/>.</param>
    /// <returns>The current <see cref="PmqIdentityOptions"/> instance for chaining.</returns>
    public PmqIdentityOptions UseLocal(Action<LocalSettings>? configure = null)
    {
        ModeOverride = IdentityMode.Local;
        LocalConfigure = configure;
        return this;
    }

    /// <summary>
    /// Configures additional authorization policies.
    /// </summary>
    /// <param name="configure">A callback to customize <see cref="AuthorizationOptions"/>.</param>
    /// <returns>The current <see cref="PmqIdentityOptions"/> instance for chaining.</returns>
    public PmqIdentityOptions ConfigureAuthorization(Action<AuthorizationOptions> configure)
    {
        AuthorizationConfigure = configure;
        return this;
    }

    /// <summary>
    /// Configures how JWT claims are mapped to user properties.
    /// </summary>
    /// <param name="configure">A callback to customize <see cref="ClaimsMappingOptions"/>.</param>
    /// <returns>The current <see cref="PmqIdentityOptions"/> instance for chaining.</returns>
    public PmqIdentityOptions ConfigureClaimsMapping(Action<ClaimsMappingOptions> configure)
    {
        ClaimsMappingConfigure = configure;
        return this;
    }
}
