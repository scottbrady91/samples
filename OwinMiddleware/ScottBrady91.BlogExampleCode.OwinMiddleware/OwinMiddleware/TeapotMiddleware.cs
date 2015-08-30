namespace ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware
{
    using System;
    using System.Threading.Tasks;

    using Microsoft.Owin;

    using ScottBrady91.BlogExampleCode.OwinMiddleware.OwinMiddleware.Configuration;

    public sealed class TeapotMiddleware : OwinMiddleware
    {
        private readonly TeapotOptions options;

        public TeapotMiddleware(OwinMiddleware next, TeapotOptions options)
            : base(next)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            this.options = options;
        }

        public async override Task Invoke(IOwinContext context)
        {
            context.Response.Cookies.Append("Biscuit", this.options.Biscuit);
            context.Response.StatusCode = 418;
            await this.Next.Invoke(context);
        }
    }
}