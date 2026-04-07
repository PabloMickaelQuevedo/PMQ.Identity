using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace PMQ.Identity;

/// <summary>
/// Default <see cref="ITokenService"/> implementation that generates JWT tokens using symmetric key signing.
/// </summary>
internal sealed class JwtTokenService : ITokenService
{
    private readonly LocalSettings _settings;

    /// <summary>
    /// Initializes a new instance of <see cref="JwtTokenService"/>.
    /// </summary>
    /// <param name="settings">The identity settings containing local token configuration.</param>
    public JwtTokenService(IOptions<IdentitySettings> settings)
    {
        _settings = settings.Value.Local;
    }

    /// <inheritdoc />
    public Task<TokenResult> GenerateTokenAsync(IIdentityUser user, CancellationToken cancellationToken = default)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SecretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        claims.AddRange(user.Claims);

        var now = DateTime.UtcNow;

        var token = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: _settings.Audience,
            claims: claims,
            notBefore: now,
            expires: now.AddMinutes(_settings.TokenExpirationMinutes),
            signingCredentials: credentials);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return Task.FromResult(new TokenResult
        {
            AccessToken = tokenString,
            ExpiresIn = _settings.TokenExpirationMinutes * 60
        });
    }
}
