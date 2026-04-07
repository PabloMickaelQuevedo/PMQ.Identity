namespace PMQ.Identity;

/// <summary>
/// Abstracts user persistence. Implement this interface to integrate with your data store.
/// </summary>
public interface IUserStore
{
    /// <summary>
    /// Finds a user by their email address.
    /// </summary>
    /// <param name="email">The email address to look up.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The matching <see cref="IIdentityUser"/>, or <see langword="null"/> if not found.</returns>
    Task<IIdentityUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a user by their unique identifier.
    /// </summary>
    /// <param name="id">The user identifier.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The matching <see cref="IIdentityUser"/>, or <see langword="null"/> if not found.</returns>
    Task<IIdentityUser?> FindByIdAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the stored password hash for the specified user.
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The password hash, or <see langword="null"/> if not found.</returns>
    Task<string?> GetPasswordHashAsync(string userId, CancellationToken cancellationToken = default);
}
