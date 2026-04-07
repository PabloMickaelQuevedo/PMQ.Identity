using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;

namespace PMQ.Identity;

/// <summary>
/// Configures JWT Bearer authentication for an external OIDC/JWT identity provider.
/// </summary>
internal static class ExternalIdentitySetup
{
    /// <summary>
    /// Registers authentication services using the provided <see cref="ExternalSettings"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="settings">The external identity provider settings.</param>
    internal static void Configure(IServiceCollection services, ExternalSettings settings)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = settings.RequireHttpsMetadata;
            options.Authority = settings.Authority;
            options.Audience = settings.Audience;

            settings.ConfigureTokenValidation?.Invoke(options.TokenValidationParameters);

            if (settings.ConfigureEvents is not null)
            {
                options.Events ??= new JwtBearerEvents();
                settings.ConfigureEvents(options.Events);
            }
        });
    }
}
