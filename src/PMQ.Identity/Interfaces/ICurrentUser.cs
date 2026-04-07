using System.Security.Claims;

namespace PMQ.Identity;

/// <summary>
/// Provides access to the current authenticated user's identity information.
/// </summary>
public interface ICurrentUser
{
    /// <summary>
    /// Gets a value indicating whether the current user is authenticated.
    /// </summary>
    bool IsAuthenticated { get; }

    /// <summary>
    /// Gets the current user's unique identifier, or <see langword="null"/> if not authenticated.
    /// </summary>
    string? Id { get; }

    /// <summary>
    /// Gets the current user's email address, or <see langword="null"/> if not available.
    /// </summary>
    string? Email { get; }

    /// <summary>
    /// Gets the roles assigned to the current user.
    /// </summary>
    IReadOnlyCollection<string> Roles { get; }

    /// <summary>
    /// Finds the first claim value that matches the specified <paramref name="claimType"/>.
    /// </summary>
    /// <param name="claimType">The claim type to search for.</param>
    /// <returns>The claim value, or <see langword="null"/> if not found.</returns>
    string? FindClaim(string claimType);

    /// <summary>
    /// Finds all claim values that match the specified <paramref name="claimType"/>.
    /// </summary>
    /// <param name="claimType">The claim type to search for.</param>
    /// <returns>An enumerable of matching claim values.</returns>
    IEnumerable<string> FindClaims(string claimType);
}
