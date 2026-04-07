namespace PMQ.Identity;

/// <summary>
/// Represents the result of a successful authentication, containing the access token and its expiration.
/// </summary>
public sealed class TokenResult
{
    /// <summary>
    /// Gets the JWT access token.
    /// </summary>
    public required string AccessToken { get; init; }

    /// <summary>
    /// Gets the token lifetime in seconds.
    /// </summary>
    public required int ExpiresIn { get; init; }
}
