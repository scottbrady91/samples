namespace ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware.Handlers
{
    using Owin;

    using ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware.Configuration;

    internal static class TeapotMiddlewareHandler
    {
        public static IAppBuilder UseTeapotMiddleware(this IAppBuilder app, TeapotOptions options)
        {
            app.Use<TeapotMiddleware>(options);

            return app;
        }
    }
}