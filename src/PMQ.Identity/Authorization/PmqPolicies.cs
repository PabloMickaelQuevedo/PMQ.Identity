namespace PMQ.Identity;

/// <summary>
/// Provides built-in authorization policy names used by PMQ.Identity.
/// </summary>
public static class PmqPolicies
{
    /// <summary>
    /// Policy that requires the user to be authenticated.
    /// </summary>
    public const string Authenticated = nameof(Authenticated);

    /// <summary>
    /// Policy that restricts access to users with the "Admin" role.
    /// </summary>
    public const string AdminOnly = nameof(AdminOnly);

    /// <summary>
    /// Returns a dynamic policy name that requires the specified role.
    /// </summary>
    /// <param name="role">The role name to require.</param>
    /// <returns>A policy name in the format <c>RequireRole:{role}</c>.</returns>
    public static string HasRole(string role) => $"RequireRole:{role}";
}
