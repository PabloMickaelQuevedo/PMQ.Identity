using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace PMQ.Identity;

/// <summary>
/// Settings for local (self-issued JWT) identity configuration.
/// </summary>
public sealed class LocalSettings
{
    /// <summary>
    /// Gets or sets the token issuer.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expected audience for token validation.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the symmetric secret key used to sign and validate tokens.
    /// </summary>
    public string SecretKey { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the token lifetime in minutes. Defaults to <c>60</c>.
    /// </summary>
    public int TokenExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Gets or sets an optional callback to further configure <see cref="TokenValidationParameters"/>.
    /// </summary>
    public Action<TokenValidationParameters>? ConfigureTokenValidation { get; set; }

    /// <summary>
    /// Gets or sets an optional callback to configure <see cref="JwtBearerEvents"/>.
    /// </summary>
    public Action<JwtBearerEvents>? ConfigureEvents { get; set; }
}
