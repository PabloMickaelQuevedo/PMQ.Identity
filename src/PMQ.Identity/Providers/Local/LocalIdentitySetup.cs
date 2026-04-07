using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace PMQ.Identity;

/// <summary>
/// Configures JWT Bearer authentication with locally-issued tokens and registers <see cref="JwtTokenService"/>.
/// </summary>
internal static class LocalIdentitySetup
{
    /// <summary>
    /// Registers authentication and token services using the provided <see cref="LocalSettings"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="settings">The local identity settings.</param>
    internal static void Configure(IServiceCollection services, LocalSettings settings)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings.SecretKey));

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = settings.Issuer,
                ValidateAudience = true,
                ValidAudience = settings.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(1)
            };

            settings.ConfigureTokenValidation?.Invoke(options.TokenValidationParameters);

            if (settings.ConfigureEvents is not null)
            {
                options.Events ??= new JwtBearerEvents();
                settings.ConfigureEvents(options.Events);
            }
        });

        services.AddSingleton<ITokenService, JwtTokenService>();
    }
}
