using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Options;
using Shouldly;
using Xunit;

namespace PMQ.Identity.Tests.Authorization;

public class PmqPolicyProviderTests
{
    private PmqPolicyProvider CreateProvider()
    {
        var options = Options.Create(new AuthorizationOptions());
        return new PmqPolicyProvider(options);
    }

    [Fact]
    public async Task GetPolicyAsync_HasRolePolicy_ReturnsPolicyWithRole()
    {
        var provider = CreateProvider();
        var policyName = PmqPolicies.HasRole("Manager");

        var policy = await provider.GetPolicyAsync(policyName);

        policy.ShouldNotBeNull();
        policy!.Requirements.ShouldContain(r => r is RolesAuthorizationRequirement);
        var roleReq = policy.Requirements.OfType<RolesAuthorizationRequirement>().Single();
        roleReq.AllowedRoles.ShouldContain("Manager");
    }

    [Fact]
    public async Task GetPolicyAsync_HasRolePolicy_RequiresAuthentication()
    {
        var provider = CreateProvider();
        var policyName = PmqPolicies.HasRole("Editor");

        var policy = await provider.GetPolicyAsync(policyName);

        policy.ShouldNotBeNull();
        policy!.Requirements.ShouldContain(r => r is DenyAnonymousAuthorizationRequirement);
    }

    [Fact]
    public async Task GetPolicyAsync_DifferentRoles_ReturnDifferentPolicies()
    {
        var provider = CreateProvider();

        var adminPolicy = await provider.GetPolicyAsync(PmqPolicies.HasRole("Admin"));
        var userPolicy = await provider.GetPolicyAsync(PmqPolicies.HasRole("User"));

        var adminRoles = adminPolicy!.Requirements.OfType<RolesAuthorizationRequirement>().Single();
        var userRoles = userPolicy!.Requirements.OfType<RolesAuthorizationRequirement>().Single();

        adminRoles.AllowedRoles.ShouldContain("Admin");
        userRoles.AllowedRoles.ShouldContain("User");
    }

    [Fact]
    public async Task GetPolicyAsync_UnknownPolicy_ReturnsNull()
    {
        var provider = CreateProvider();

        var policy = await provider.GetPolicyAsync("NonExistentPolicy");

        policy.ShouldBeNull();
    }

    [Fact]
    public async Task GetPolicyAsync_StaticPolicies_StillWork()
    {
        var authOptions = new AuthorizationOptions();
        authOptions.AddPolicy(PmqPolicies.Authenticated, p => p.RequireAuthenticatedUser());
        var provider = new PmqPolicyProvider(Options.Create(authOptions));

        var policy = await provider.GetPolicyAsync(PmqPolicies.Authenticated);

        policy.ShouldNotBeNull();
        policy!.Requirements.ShouldContain(r => r is DenyAnonymousAuthorizationRequirement);
    }

    [Fact]
    public async Task GetDefaultPolicyAsync_ReturnsDefaultPolicy()
    {
        var provider = CreateProvider();

        var policy = await provider.GetDefaultPolicyAsync();

        policy.ShouldNotBeNull();
    }

    [Fact]
    public void HasRole_GeneratesCorrectPolicyName()
    {
        PmqPolicies.HasRole("Manager").ShouldBe("RequireRole:Manager");
        PmqPolicies.HasRole("Admin").ShouldBe("RequireRole:Admin");
    }
}
