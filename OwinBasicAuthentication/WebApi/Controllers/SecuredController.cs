using System.Web.Http;

namespace WebApi.Controllers
{
    [Authorize]
    public class SecuredController : ApiController
    {
        [HttpGet]
        [Route("Secured")]
        public IHttpActionResult Get()
        {
            return Json("Authenticated!");
        }
    }
}