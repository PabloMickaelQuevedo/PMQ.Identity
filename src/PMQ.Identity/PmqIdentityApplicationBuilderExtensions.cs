using Microsoft.AspNetCore.Builder;

namespace PMQ.Identity;

/// <summary>
/// Extension methods for configuring the PMQ.Identity middleware pipeline.
/// </summary>
public static class PmqIdentityApplicationBuilderExtensions
{
    /// <summary>
    /// Adds authentication and authorization middleware to the application pipeline.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The <see cref="IApplicationBuilder"/> for chaining.</returns>
    public static IApplicationBuilder UsePmqIdentity(this IApplicationBuilder app)
    {
        app.UseAuthentication();
        app.UseAuthorization();
        return app;
    }
}
