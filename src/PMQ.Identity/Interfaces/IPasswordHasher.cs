namespace PMQ.Identity;

/// <summary>
/// Abstracts password hashing and verification. Implement this interface with your preferred hashing algorithm (e.g., BCrypt, Argon2).
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Produces a hash of the given <paramref name="password"/>.
    /// </summary>
    /// <param name="password">The plain-text password to hash.</param>
    /// <returns>The hashed password.</returns>
    string Hash(string password);

    /// <summary>
    /// Verifies that a <paramref name="password"/> matches the given <paramref name="hash"/>.
    /// </summary>
    /// <param name="password">The plain-text password to verify.</param>
    /// <param name="hash">The stored password hash.</param>
    /// <returns><see langword="true"/> if the password matches the hash; otherwise, <see langword="false"/>.</returns>
    bool Verify(string password, string hash);
}
