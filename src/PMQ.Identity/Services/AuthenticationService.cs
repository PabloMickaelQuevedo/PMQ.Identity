namespace PMQ.Identity;

/// <summary>
/// Handles user authentication by validating credentials and issuing tokens.
/// </summary>
public sealed class AuthenticationService
{
    private readonly IUserStore _userStore;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ITokenService _tokenService;

    /// <summary>
    /// Initializes a new instance of <see cref="AuthenticationService"/>.
    /// </summary>
    /// <param name="userStore">The user persistence store.</param>
    /// <param name="passwordHasher">The password hashing implementation.</param>
    /// <param name="tokenService">The token generation service.</param>
    public AuthenticationService(IUserStore userStore, IPasswordHasher passwordHasher, ITokenService tokenService)
    {
        _userStore = userStore;
        _passwordHasher = passwordHasher;
        _tokenService = tokenService;
    }

    /// <summary>
    /// Authenticates a user with the given credentials.
    /// </summary>
    /// <param name="email">The user's email address.</param>
    /// <param name="password">The user's plain-text password.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A <see cref="TokenResult"/> if authentication succeeds; otherwise, <see langword="null"/>.</returns>
    public async Task<TokenResult?> AuthenticateAsync(string email, string password, CancellationToken cancellationToken = default)
    {
        var user = await _userStore.FindByEmailAsync(email, cancellationToken);
        if (user is null)
        {
            // Prevent user enumeration via timing attack:
            // perform a dummy hash operation so the response time
            // is similar whether or not the user exists.
            _passwordHasher.Verify(password, string.Empty);
            return null;
        }

        var hash = await _userStore.GetPasswordHashAsync(user.Id, cancellationToken);
        if (hash is null || !_passwordHasher.Verify(password, hash))
            return null;

        return await _tokenService.GenerateTokenAsync(user, cancellationToken);
    }
}
