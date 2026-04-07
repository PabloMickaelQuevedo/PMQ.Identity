namespace PMQ.Identity;

/// <summary>
/// Specifies the identity authentication mode.
/// </summary>
public enum IdentityMode
{
    /// <summary>
    /// Use an external OIDC/JWT identity provider.
    /// </summary>
    External,

    /// <summary>
    /// Use locally-issued JWT tokens.
    /// </summary>
    Local
}
