using System.Security.Claims;

namespace PMQ.Identity;

/// <summary>
/// Represents a user in the identity system. Implement this interface in your application's user entity.
/// </summary>
public interface IIdentityUser
{
    /// <summary>
    /// Gets the user's unique identifier.
    /// </summary>
    string Id { get; }

    /// <summary>
    /// Gets the user's email address.
    /// </summary>
    string Email { get; }

    /// <summary>
    /// Gets the claims associated with this user, used for token generation.
    /// </summary>
    IReadOnlyCollection<Claim> Claims { get; }
}
