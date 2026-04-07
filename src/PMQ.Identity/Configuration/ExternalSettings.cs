using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace PMQ.Identity;

/// <summary>
/// Settings for external (OIDC/JWT) identity provider configuration.
/// </summary>
public sealed class ExternalSettings
{
    /// <summary>
    /// Gets or sets the authority URL of the external identity provider (e.g., <c>https://login.provider.com</c>).
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expected audience for token validation.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets whether HTTPS is required for the metadata endpoint. Defaults to <see langword="true"/>.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Gets or sets an optional callback to further configure <see cref="TokenValidationParameters"/>.
    /// </summary>
    public Action<TokenValidationParameters>? ConfigureTokenValidation { get; set; }

    /// <summary>
    /// Gets or sets an optional callback to configure <see cref="JwtBearerEvents"/>.
    /// </summary>
    public Action<JwtBearerEvents>? ConfigureEvents { get; set; }
}
