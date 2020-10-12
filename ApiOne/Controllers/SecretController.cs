using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;

namespace ApiOne.Controllers
{
    public class SecretController : Controller
    {
        [Route("/secret")]
        //[Authorize(Policy = "ERP.Class.Select")]
        [Authorize("ERP.Class.Select")]
        //[Authorize(Policy ="ERP.Class.Insert")]
        //[Authorize(Policy ="ERP.Class.Update")]
        //[Authorize(Policy ="ERP.Class.Delete")]
        public async Task<string> Index()
        {
            
            var accessToken123 = await HttpContext.GetTokenAsync("access_token");
            var idToken123 = await HttpContext.GetTokenAsync("id_token");
            var claims = User.Claims.ToList();

            return "secret message from ApiOne";
        }
        
    }
}
