namespace ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware.Handlers
{
    using Owin;

    internal static class OrderMiddlewareHandler
    {
        public static IAppBuilder UseOrderMiddleware(this IAppBuilder app)
        {
            app.Use<OrderMiddleware>();

            return app;
        } 
    }
}