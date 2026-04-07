namespace PMQ.Identity;

/// <summary>
/// Root configuration settings for PMQ.Identity, typically bound from the <c>IdentitySettings</c> configuration section.
/// </summary>
public sealed class IdentitySettings
{
    /// <summary>
    /// The configuration section name. Value is <c>"IdentitySettings"</c>.
    /// </summary>
    public const string SectionName = "IdentitySettings";

    /// <summary>
    /// Gets or sets the identity mode. Defaults to <see cref="IdentityMode.External"/>.
    /// </summary>
    public IdentityMode Mode { get; set; } = IdentityMode.External;

    /// <summary>
    /// Gets or sets the external identity provider settings.
    /// </summary>
    public ExternalSettings External { get; set; } = new();

    /// <summary>
    /// Gets or sets the local (self-issued JWT) identity settings.
    /// </summary>
    public LocalSettings Local { get; set; } = new();
}
