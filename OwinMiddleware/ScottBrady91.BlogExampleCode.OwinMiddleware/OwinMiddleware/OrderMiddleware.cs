namespace ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin;

    public sealed class OrderMiddleware : OwinMiddleware
    {
        public OrderMiddleware(OwinMiddleware next)
            : base(next)
        {
        }

        public async override Task Invoke(IOwinContext context)
        {
            // user login
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, "Scott"));
            claims.Add(new Claim(ClaimTypes.Email, "scott@scottbrady91.com"));

            var id = new ClaimsIdentity(claims, "cookie");

            context.Authentication.SignIn(id);

            // send file
            context.Response.ContentType = @"image/jpeg";
            await context.Response.SendFileAsync(@"~/img/teapot.jpg");
        }
    }
}