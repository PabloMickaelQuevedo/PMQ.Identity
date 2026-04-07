using System.Security.Claims;

namespace PMQ.Identity.Tests;

internal sealed class TestIdentityUser : IIdentityUser
{
    public string Id { get; }
    public string Email { get; }
    public IReadOnlyCollection<Claim> Claims { get; }

    public TestIdentityUser(string id, string email, IReadOnlyCollection<Claim> claims)
    {
        Id = id;
        Email = email;
        Claims = claims;
    }
}
