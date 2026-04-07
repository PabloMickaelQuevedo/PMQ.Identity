using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace PMQ.Identity.Tests;

public class PmqIdentityServiceCollectionExtensionsTests
{
    [Fact]
    public void AddPmqIdentity_ExternalMode_ConfiguresAuthentication()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "External",
            ["IdentitySettings:External:Authority"] = "https://idp.example.com",
            ["IdentitySettings:External:Audience"] = "my-api",
        });

        services.AddPmqIdentity(configuration);

        var provider = services.BuildServiceProvider();
        services.Should().Contain(s => s.ServiceType.Name == "IAuthenticationService");
    }

    [Fact]
    public void AddPmqIdentity_LocalMode_RegistersTokenServiceAndAuthService()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "Local",
            ["IdentitySettings:Local:Issuer"] = "PMQ",
            ["IdentitySettings:Local:Audience"] = "my-api",
            ["IdentitySettings:Local:SecretKey"] = "ThisIsASecretKeyForTestingPurposesOnly!AtLeast32Chars",
        });

        services.AddPmqIdentity(configuration);

        services.Should().Contain(s => s.ServiceType == typeof(ITokenService));
        services.Should().Contain(s => s.ServiceType == typeof(AuthenticationService));
    }

    [Fact]
    public void AddPmqIdentity_ExternalMode_MissingAuthority_Throws()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "External",
            ["IdentitySettings:External:Audience"] = "my-api",
        });

        var act = () => services.AddPmqIdentity(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Authority*required*");
    }

    [Fact]
    public void AddPmqIdentity_ExternalMode_MissingAudience_Throws()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "External",
            ["IdentitySettings:External:Authority"] = "https://idp.example.com",
        });

        var act = () => services.AddPmqIdentity(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Audience*required*");
    }

    [Fact]
    public void AddPmqIdentity_LocalMode_MissingSecretKey_Throws()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "Local",
            ["IdentitySettings:Local:Issuer"] = "PMQ",
            ["IdentitySettings:Local:Audience"] = "my-api",
        });

        var act = () => services.AddPmqIdentity(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*SecretKey*required*");
    }

    [Fact]
    public void AddPmqIdentity_LocalMode_ShortSecretKey_Throws()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "Local",
            ["IdentitySettings:Local:Issuer"] = "PMQ",
            ["IdentitySettings:Local:Audience"] = "my-api",
            ["IdentitySettings:Local:SecretKey"] = "short",
        });

        var act = () => services.AddPmqIdentity(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*at least 32 characters*");
    }

    [Fact]
    public void AddPmqIdentity_LambdaOverridesMode()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "External",
            ["IdentitySettings:External:Authority"] = "https://idp.example.com",
            ["IdentitySettings:External:Audience"] = "my-api",
            ["IdentitySettings:Local:Issuer"] = "PMQ",
            ["IdentitySettings:Local:Audience"] = "my-api",
            ["IdentitySettings:Local:SecretKey"] = "ThisIsASecretKeyForTestingPurposesOnly!AtLeast32Chars",
        });

        services.AddPmqIdentity(configuration, options => options.UseLocal());

        services.Should().Contain(s => s.ServiceType == typeof(ITokenService));
    }

    [Fact]
    public void AddPmqIdentity_RegistersICurrentUser()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "External",
            ["IdentitySettings:External:Authority"] = "https://idp.example.com",
            ["IdentitySettings:External:Audience"] = "my-api",
        });

        services.AddPmqIdentity(configuration);

        services.Should().Contain(s => s.ServiceType == typeof(ICurrentUser));
    }

    [Fact]
    public void AddPmqIdentity_RegistersClaimsMappingOptions()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "External",
            ["IdentitySettings:External:Authority"] = "https://idp.example.com",
            ["IdentitySettings:External:Audience"] = "my-api",
        });

        services.AddPmqIdentity(configuration);

        services.Should().Contain(s => s.ServiceType == typeof(ClaimsMappingOptions));
    }

    [Fact]
    public void AddPmqIdentity_RegistersPolicyProvider()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "External",
            ["IdentitySettings:External:Authority"] = "https://idp.example.com",
            ["IdentitySettings:External:Audience"] = "my-api",
        });

        services.AddPmqIdentity(configuration);

        services.Should().Contain(s => s.ServiceType == typeof(IAuthorizationPolicyProvider));
    }

    [Fact]
    public void AddPmqIdentity_CustomClaimsMapping_Applied()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["IdentitySettings:Mode"] = "External",
            ["IdentitySettings:External:Authority"] = "https://idp.example.com",
            ["IdentitySettings:External:Audience"] = "my-api",
        });

        services.AddPmqIdentity(configuration, options =>
        {
            options.ConfigureClaimsMapping(mapping =>
            {
                mapping.RoleClaimType = "realm_access.roles";
                mapping.UserIdClaimType = "preferred_username";
            });
        });

        var provider = services.BuildServiceProvider();
        var mapping = provider.GetRequiredService<ClaimsMappingOptions>();
        mapping.RoleClaimType.Should().Be("realm_access.roles");
        mapping.UserIdClaimType.Should().Be("preferred_username");
    }

    private static IConfiguration BuildConfiguration(Dictionary<string, string?> values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
}
