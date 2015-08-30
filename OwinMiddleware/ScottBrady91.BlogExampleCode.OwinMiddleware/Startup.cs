using Microsoft.Owin;

using ScottBrady91.BlogExampleCode.OwinMiddleware;

[assembly: OwinStartup(typeof(Startup))]

namespace ScottBrady91.BlogExampleCode.OwinMiddleware
{
    using Microsoft.Owin.Security.Cookies;

    using Owin;

    using ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware;
    using ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware.Configuration;
    using ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware.Handlers;

    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions { AuthenticationType = "cookie" });
            
            //app.Use<TeapotMiddleware>();
            //app.Use(typeof(TeapotMiddleware));
            app.UseTeapotMiddleware(new TeapotOptions { Biscuit = "Hobnob" });

            app.UseOrderMiddleware();
        }
    }
}