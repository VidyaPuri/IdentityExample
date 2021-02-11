using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Threading.Tasks;
using EditorClient.Models;

namespace EditorClient.Controllers
{
    public partial class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;

        private UserModel _user = new UserModel();

        public UserModel User
        {
            get { return _user; }
            private set
            {
                _user = value;
                if (_user != null)
                {
                    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                    _user.DecodedAccessToken = handler.ReadJwtToken(_user.AccessToken);
                }
            }
        }

        public HomeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        private async Task<HttpResponseMessage> SecuredGetRequest(string url)
        {
            var token = await HttpContext.GetTokenAsync("access_token");
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            return await client.GetAsync(url);
        }

        //[Authorize]
        public async Task<IActionResult> Index()
        {
            // retrieve access token
            var serverClient = _httpClientFactory.CreateClient();
            var discoveryDocument = await serverClient.GetDiscoveryDocumentAsync("https://identityserver-test.brinox.si/");

            var rt = await serverClient.RequestClientCredentialsTokenAsync(
             new ClientCredentialsTokenRequest
             {
                 GrantType = "client_credentials",
                 Address = discoveryDocument.TokenEndpoint,
                 ClientId = "BRILink2",
                 ClientSecret = "link_secret",
                 Scope = "ABPIdentityServer",
             });

            User.AccessToken = rt.AccessToken;
            User.RefreshToken = rt.RefreshToken;

            var _accessToken = new JwtSecurityTokenHandler().ReadJwtToken(User.AccessToken);
            //var infoClaims = userInfo.Claims;
            var claims = _accessToken.Claims;

            return Ok();
        }
    }
}
//      