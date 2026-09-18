using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Shouldly;
using Xunit;

namespace PMQ.Identity.Tests.Services;

public class CurrentUserTests
{
    private static CurrentUser CreateCurrentUser(ClaimsPrincipal? principal = null, ClaimsMappingOptions? mapping = null)
    {
        var httpContext = new DefaultHttpContext();
        if (principal is not null)
            httpContext.User = principal;

        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);

        return new CurrentUser(accessor, mapping ?? new ClaimsMappingOptions());
    }

    [Fact]
    public void IsAuthenticated_NoUser_ReturnsFalse()
    {
        var sut = CreateCurrentUser();

        sut.IsAuthenticated.ShouldBeFalse();
    }

    [Fact]
    public void IsAuthenticated_AuthenticatedUser_ReturnsTrue()
    {
        var identity = new ClaimsIdentity([new Claim("sub", "1")], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var sut = CreateCurrentUser(principal);

        sut.IsAuthenticated.ShouldBeTrue();
    }

    [Fact]
    public void Id_ReturnsSubClaim()
    {
        var identity = new ClaimsIdentity([new Claim("sub", "42")], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var sut = CreateCurrentUser(principal);

        sut.Id.ShouldBe("42");
    }

    [Fact]
    public void Email_ReturnsEmailClaim()
    {
        var identity = new ClaimsIdentity([new Claim("email", "user@example.com")], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var sut = CreateCurrentUser(principal);

        sut.Email.ShouldBe("user@example.com");
    }

    [Fact]
    public void Roles_ReturnsAllRoleClaims()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Role, "Admin"),
            new Claim(ClaimTypes.Role, "User"),
        ], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var sut = CreateCurrentUser(principal);

        sut.Roles.ShouldBe(["Admin", "User"], ignoreOrder: true);
    }

    [Fact]
    public void Roles_NoRoles_ReturnsEmpty()
    {
        var identity = new ClaimsIdentity([new Claim("sub", "1")], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var sut = CreateCurrentUser(principal);

        sut.Roles.ShouldBeEmpty();
    }

    [Fact]
    public void Id_NullHttpContext_ReturnsNull()
    {
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns((HttpContext?)null);

        var sut = new CurrentUser(accessor, new ClaimsMappingOptions());

        sut.IsAuthenticated.ShouldBeFalse();
        sut.Id.ShouldBeNull();
        sut.Email.ShouldBeNull();
        sut.Roles.ShouldBeEmpty();
    }

    [Fact]
    public void FindClaim_ExistingClaim_ReturnsValue()
    {
        var identity = new ClaimsIdentity([new Claim("tenant_id", "abc")], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var sut = CreateCurrentUser(principal);

        sut.FindClaim("tenant_id").ShouldBe("abc");
    }

    [Fact]
    public void FindClaim_NonExistingClaim_ReturnsNull()
    {
        var identity = new ClaimsIdentity([new Claim("sub", "1")], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var sut = CreateCurrentUser(principal);

        sut.FindClaim("nonexistent").ShouldBeNull();
    }

    [Fact]
    public void FindClaims_MultipleClaims_ReturnsAll()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim("permission", "read"),
            new Claim("permission", "write"),
            new Claim("permission", "delete"),
        ], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var sut = CreateCurrentUser(principal);

        sut.FindClaims("permission").ShouldBe(["read", "write", "delete"], ignoreOrder: true);
    }

    [Fact]
    public void CustomMapping_Id_UsesConfiguredClaimType()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim("custom_uid", "99"),
            new Claim("sub", "should-not-use-this"),
        ], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var mapping = new ClaimsMappingOptions { UserIdClaimType = "custom_uid" };
        var sut = CreateCurrentUser(principal, mapping);

        sut.Id.ShouldBe("99");
    }

    [Fact]
    public void CustomMapping_Email_UsesConfiguredClaimType()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim("preferred_email", "custom@example.com"),
        ], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var mapping = new ClaimsMappingOptions { EmailClaimType = "preferred_email" };
        var sut = CreateCurrentUser(principal, mapping);

        sut.Email.ShouldBe("custom@example.com");
    }

    [Fact]
    public void CustomMapping_Roles_UsesConfiguredClaimType()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim("realm_roles", "Admin"),
            new Claim("realm_roles", "Manager"),
            new Claim(ClaimTypes.Role, "should-not-use-this"),
        ], "Bearer");
        var principal = new ClaimsPrincipal(identity);

        var mapping = new ClaimsMappingOptions { RoleClaimType = "realm_roles" };
        var sut = CreateCurrentUser(principal, mapping);

        sut.Roles.ShouldBe(["Admin", "Manager"], ignoreOrder: true);
    }
}
