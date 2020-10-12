using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Volo.Abp.Account.Web.Areas.Account.Controllers.Models;

namespace ApiTwo.Controllers
{
    public partial class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public HomeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [Route("/")]
        public async Task<IActionResult> Index()
        {
            // retrieve access token
            var serverClient = _httpClientFactory.CreateClient();

            var discoveryDocument = await serverClient.GetDiscoveryDocumentAsync("https://localhost:44346/");
            //var tokenResponse = await serverClient.RequestClientCredentialsTokenAsync(
            //    new ClientCredentialsTokenRequest
            //    {
            //        GrantType = "authorization_code",
            //        Address = discoveryDocument.TokenEndpoint,
            //        ClientId = "Authentication_App",
            //        ClientSecret = "client_secret",
            //        //UserName =  "testuser",
            //        //UserPassword ="Test123!",<
            //        Scope = "Authentication"
            //    });

            //PasswordTokenRequest editorPTR = new PasswordTokenRequest()
            //{
            //    GrantType = "password",
            //    Address = discoveryDocument.TokenEndpoint,
            //    ClientId = "client_editor_v2",
            //    ClientSecret = "editor_secret",
            //    UserName = "testuser",
            //    Password = "Test123!",
            //};

            var tokenR = await serverClient.RequestPasswordTokenAsync(
            new PasswordTokenRequest
            {
                GrantType = "password",
                Address = discoveryDocument.TokenEndpoint,
                ClientId = "Authentication_App",
                UserName = "testuser",
                Password = "Test123!",
                Scope = "ApiOne",
            });

            var it = tokenR.IdentityToken;

            //var accessToken123 = await HttpContext.GetTokenAsync("access_token");
            //var idToken123 = await HttpContext.GetTokenAsync("id_token");

            //var tkn = await serverClient.Re

            //var accessToken = tokenResponse.AccessToken;
            var aT = tokenR.AccessToken;
            //var _accessToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
            var _accessToken1 = new JwtSecurityTokenHandler().ReadJwtToken(aT);

            // retrieve secret data
            var apiClient = _httpClientFactory.CreateClient();

            apiClient.SetBearerToken(tokenR.AccessToken);

            var response = await apiClient.GetAsync("https://localhost:44308/secret");
            //var response2 = await apiClient.GetAsync("https://localhost:44346/api/language-management/languages");

            var content = await response.Content.ReadAsStringAsync();
            //var content2 = await response2.Content.ReadAsStringAsync();

            return Ok(new
            {
                access_token = tokenR.AccessToken,
                msg = _accessToken1.Claims,
                refresh_token = tokenR.RefreshToken,
                response = content
            });
        }

        [Route("/login")]
        public async Task<IActionResult> Login()
        {
            Volo.Abp.Account.Web.Areas.Account.Controllers.Models.UserLoginInfo userLoginInfo = new Volo.Abp.Account.Web.Areas.Account.Controllers.Models.UserLoginInfo
            {
                UserNameOrEmailAddress = "testuser",
                Password = "Test123!",
                RememberMe = false,
            };

            string userNameOrEmailAddress = "testuser";
            string password = "Test123!";
            //bool rememberMe = false;
            string AuthenticationUrl = "https://localhost:44346/api/account/login";

            //FormUrlEncodedContent content = new FormUrlEncodedContent(new[] {
            //        //new KeyValuePair<string, string>("grant_type", "password"),
            //        new KeyValuePair<string, string>("userNameOrEmailAddress", userNameOrEmailAddress),
            //        new KeyValuePair<string, string>("password", password),
            //    });

            //Controllers.UserLoginInfo content 
            //_oidcClient = new OidcClient();

            var usercontent2 = new StringContent(JsonConvert.SerializeObject(userLoginInfo), Encoding.UTF8, "application/json");

            var serverClient = _httpClientFactory.CreateClient();
            //var response = await serverClient.GetAsync("https://localhost:44346/connect/authorize");
            var serverResponse = await serverClient.PostAsync(AuthenticationUrl, usercontent2);

            if (serverResponse.StatusCode == System.Net.HttpStatusCode.OK)
            {
                var data = await serverResponse.Content.ReadAsStringAsync();
                AbpLoginResult xx = JsonConvert.DeserializeObject(data) as AbpLoginResult;
            }

            return Ok(new
            {
                message = usercontent2,
                respones = serverResponse.Content
            }) ;
        }
    }
}
