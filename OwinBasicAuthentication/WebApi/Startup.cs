using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;
using Owin;
using Thinktecture.IdentityModel.Owin;
using WebApi;

[assembly: OwinStartup(typeof (Startup))]

namespace WebApi
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();
            config.MapHttpAttributeRoutes();

            app.UseBasicAuthentication(new BasicAuthenticationOptions("SecureApi",
                async (username, password) => await Authenticate(username, password)));

            app.UseWebApi(config);
        }

        private async Task<IEnumerable<Claim>> Authenticate(string username, string password)
        {
            // authenticate user
            if (username == password)
            {
                return new List<Claim>
                {
                    new Claim("name", username)
                };
            }

            return null;
        }
    }
}