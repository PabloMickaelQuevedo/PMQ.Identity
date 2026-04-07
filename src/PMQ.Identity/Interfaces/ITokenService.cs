namespace PMQ.Identity;

/// <summary>
/// Generates JWT tokens for authenticated users. Implement this interface if you need custom token generation logic.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Generates a JWT access token for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The authenticated user.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A <see cref="TokenResult"/> containing the access token and its expiration.</returns>
    Task<TokenResult> GenerateTokenAsync(IIdentityUser user, CancellationToken cancellationToken = default);
}
