using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace PMQ.Identity.Tests.Providers.Local;

public class JwtTokenServiceTests
{
    private readonly LocalSettings _localSettings = new()
    {
        Issuer = "TestIssuer",
        Audience = "TestAudience",
        SecretKey = "ThisIsASecretKeyForTestingPurposesOnly!AtLeast32Chars",
        TokenExpirationMinutes = 30
    };

    private JwtTokenService CreateService()
    {
        var settings = new IdentitySettings { Local = _localSettings };
        var options = Options.Create(settings);
        return new JwtTokenService(options);
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldReturnValidJwt()
    {
        var service = CreateService();
        var user = new TestIdentityUser("1", "test@example.com", []);

        var result = await service.GenerateTokenAsync(user);

        result.AccessToken.ShouldNotBeNullOrWhiteSpace();
        result.ExpiresIn.ShouldBe(30 * 60);
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldContainUserClaims()
    {
        var service = CreateService();
        var customClaims = new List<Claim> { new("role", "Admin") };
        var user = new TestIdentityUser("42", "admin@example.com", customClaims);

        var result = await service.GenerateTokenAsync(user);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result.AccessToken);

        jwt.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Sub && c.Value == "42");
        jwt.Claims.ShouldContain(c => c.Type == JwtRegisteredClaimNames.Email && c.Value == "admin@example.com");
        jwt.Claims.ShouldContain(c => c.Type == "role" && c.Value == "Admin");
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldSetCorrectIssuerAndAudience()
    {
        var service = CreateService();
        var user = new TestIdentityUser("1", "test@example.com", []);

        var result = await service.GenerateTokenAsync(user);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result.AccessToken);

        jwt.Issuer.ShouldBe("TestIssuer");
        jwt.Audiences.ShouldContain("TestAudience");
    }

    [Fact]
    public async Task GenerateTokenAsync_ShouldSetExpiration()
    {
        var service = CreateService();
        var user = new TestIdentityUser("1", "test@example.com", []);

        var result = await service.GenerateTokenAsync(user);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result.AccessToken);

        jwt.ValidTo.ShouldBe(DateTime.UtcNow.AddMinutes(30), TimeSpan.FromSeconds(5));
    }
}
