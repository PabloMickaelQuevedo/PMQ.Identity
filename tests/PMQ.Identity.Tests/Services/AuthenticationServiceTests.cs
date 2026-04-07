using FluentAssertions;
using NSubstitute;
using Xunit;

namespace PMQ.Identity.Tests.Services;

public class AuthenticationServiceTests
{
    private readonly IUserStore _userStore = Substitute.For<IUserStore>();
    private readonly IPasswordHasher _passwordHasher = Substitute.For<IPasswordHasher>();
    private readonly ITokenService _tokenService = Substitute.For<ITokenService>();
    private readonly AuthenticationService _sut;

    public AuthenticationServiceTests()
    {
        _sut = new AuthenticationService(_userStore, _passwordHasher, _tokenService);
    }

    [Fact]
    public async Task AuthenticateAsync_UserNotFound_ReturnsNull()
    {
        _userStore.FindByEmailAsync("unknown@example.com").Returns((IIdentityUser?)null);

        var result = await _sut.AuthenticateAsync("unknown@example.com", "password");

        result.Should().BeNull();
    }

    [Fact]
    public async Task AuthenticateAsync_UserNotFound_StillCallsVerify()
    {
        _userStore.FindByEmailAsync("unknown@example.com").Returns((IIdentityUser?)null);

        await _sut.AuthenticateAsync("unknown@example.com", "password");

        // Verify that a dummy hash was performed to prevent timing attacks
        _passwordHasher.Received(1).Verify("password", string.Empty);
    }

    [Fact]
    public async Task AuthenticateAsync_InvalidPassword_ReturnsNull()
    {
        var user = new TestIdentityUser("1", "user@example.com", []);
        _userStore.FindByEmailAsync("user@example.com").Returns(user);
        _userStore.GetPasswordHashAsync("1").Returns("hashed");
        _passwordHasher.Verify("wrong", "hashed").Returns(false);

        var result = await _sut.AuthenticateAsync("user@example.com", "wrong");

        result.Should().BeNull();
    }

    [Fact]
    public async Task AuthenticateAsync_NullPasswordHash_ReturnsNull()
    {
        var user = new TestIdentityUser("1", "user@example.com", []);
        _userStore.FindByEmailAsync("user@example.com").Returns(user);
        _userStore.GetPasswordHashAsync("1").Returns((string?)null);

        var result = await _sut.AuthenticateAsync("user@example.com", "password");

        result.Should().BeNull();
    }

    [Fact]
    public async Task AuthenticateAsync_ValidCredentials_ReturnsToken()
    {
        var user = new TestIdentityUser("1", "user@example.com", []);
        var expectedToken = new TokenResult { AccessToken = "jwt-token", ExpiresIn = 3600 };

        _userStore.FindByEmailAsync("user@example.com").Returns(user);
        _userStore.GetPasswordHashAsync("1").Returns("hashed");
        _passwordHasher.Verify("correct-password", "hashed").Returns(true);
        _tokenService.GenerateTokenAsync(user).Returns(expectedToken);

        var result = await _sut.AuthenticateAsync("user@example.com", "correct-password");

        result.Should().NotBeNull();
        result!.AccessToken.Should().Be("jwt-token");
        result.ExpiresIn.Should().Be(3600);
    }
}
