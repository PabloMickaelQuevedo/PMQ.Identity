using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace PMQ.Identity;

/// <summary>
/// Extension methods for registering PMQ.Identity services in the dependency injection container.
/// </summary>
public static class PmqIdentityServiceCollectionExtensions
{
    /// <summary>
    /// Registers PMQ.Identity authentication, authorization, and related services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration (must contain an <c>IdentitySettings</c> section).</param>
    /// <param name="configure">An optional callback to customize <see cref="PmqIdentityOptions"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddPmqIdentity(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<PmqIdentityOptions>? configure = null)
    {
        var settings = new IdentitySettings();
        configuration.GetSection(IdentitySettings.SectionName).Bind(settings);

        var options = new PmqIdentityOptions();
        configure?.Invoke(options);

        if (options.ModeOverride.HasValue)
            settings.Mode = options.ModeOverride.Value;

        services.Configure<IdentitySettings>(configuration.GetSection(IdentitySettings.SectionName));

        // Claims mapping
        var claimsMapping = new ClaimsMappingOptions();
        options.ClaimsMappingConfigure?.Invoke(claimsMapping);
        services.AddSingleton(claimsMapping);

        // ICurrentUser
        services.AddHttpContextAccessor();
        services.TryAddScoped<ICurrentUser, CurrentUser>();

        switch (settings.Mode)
        {
            case IdentityMode.External:
                options.ExternalConfigure?.Invoke(settings.External);
                ValidateExternalSettings(settings.External);
                ExternalIdentitySetup.Configure(services, settings.External);
                break;

            case IdentityMode.Local:
                options.LocalConfigure?.Invoke(settings.Local);
                ValidateLocalSettings(settings.Local);
                LocalIdentitySetup.Configure(services, settings.Local);
                services.AddScoped<AuthenticationService>();
                break;

            default:
                throw new InvalidOperationException($"Unknown identity mode: {settings.Mode}");
        }

        AuthorizationSetup.Configure(services, options.AuthorizationConfigure);

        return services;
    }

    private static void ValidateExternalSettings(ExternalSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.Authority))
            throw new InvalidOperationException(
                "IdentitySettings:External:Authority is required when using External mode.");

        if (string.IsNullOrWhiteSpace(settings.Audience))
            throw new InvalidOperationException(
                "IdentitySettings:External:Audience is required when using External mode.");
    }

    private static void ValidateLocalSettings(LocalSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.SecretKey))
            throw new InvalidOperationException(
                "IdentitySettings:Local:SecretKey is required when using Local mode.");

        if (string.IsNullOrWhiteSpace(settings.Issuer))
            throw new InvalidOperationException(
                "IdentitySettings:Local:Issuer is required when using Local mode.");

        if (string.IsNullOrWhiteSpace(settings.Audience))
            throw new InvalidOperationException(
                "IdentitySettings:Local:Audience is required when using Local mode.");

        if (settings.SecretKey.Length < 32)
            throw new InvalidOperationException(
                "IdentitySettings:Local:SecretKey must be at least 32 characters for HMAC-SHA256.");
    }
}
