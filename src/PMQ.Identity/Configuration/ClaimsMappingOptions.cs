using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace PMQ.Identity;

/// <summary>
/// Options for mapping JWT claim types to user properties.
/// </summary>
public sealed class ClaimsMappingOptions
{
    /// <summary>
    /// Gets or sets the claim type used to resolve the user identifier. Defaults to <see cref="JwtRegisteredClaimNames.Sub"/>.
    /// </summary>
    public string UserIdClaimType { get; set; } = JwtRegisteredClaimNames.Sub;

    /// <summary>
    /// Gets or sets the claim type used to resolve the user email. Defaults to <see cref="JwtRegisteredClaimNames.Email"/>.
    /// </summary>
    public string EmailClaimType { get; set; } = JwtRegisteredClaimNames.Email;

    /// <summary>
    /// Gets or sets the claim type used to resolve user roles. Defaults to <see cref="ClaimTypes.Role"/>.
    /// </summary>
    public string RoleClaimType { get; set; } = ClaimTypes.Role;
}
