using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

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

            var responseToken = await serverClient.RequestPasswordTokenAsync(
            new PasswordTokenRequest
            {
                GrantType = "password",
                Address = discoveryDocument.TokenEndpoint,
                ClientId = "Authentication_Editor",
                ClientSecret = "editor_secret",
                UserName = "testuser",
                Password = "Test123!",
                Scope = "",
            });

            var userInfo = await serverClient.GetUserInfoAsync(
                new UserInfoRequest
                {
                    Address = discoveryDocument.UserInfoEndpoint,
                    Token = responseToken.AccessToken
                });

            var accessToken = responseToken.AccessToken;

            var _accessToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);

            var claims = _accessToken.Claims;

            // retrieve secret data
            var apiClient = _httpClientFactory.CreateClient();

            apiClient.SetBearerToken(responseToken.AccessToken);

            var response = await apiClient.GetAsync("https://localhost:44308/secret");
            //var response2 = await apiClient.GetAsync("https://localhost:44346/api/language-management/languages");
            var content = await response.Content.ReadAsStringAsync();
            //var content2 = await response2.Content.ReadAsStringAsync();
            //var cont = JArray.Parse(content);

            return Ok(new
            {
                data = content,
            }) ;
        }

        [Route("/login")]
        public async Task<IActionResult> Login()
        {
            //Volo.Abp.Account.Web.Areas.Account.Controllers.Models.UserLoginInfo userLoginInfo = new Volo.Abp.Account.Web.Areas.Account.Controllers.Models.UserLoginInfo
            //{
            //    UserNameOrEmailAddress = "testuser",
            //    Password = "Test123!",
            //    RememberMe = false,
            //};

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

            //var usercontent2 = new StringContent(JsonConvert.SerializeObject(userLoginInfo), Encoding.UTF8, "application/json");

            //var serverClient = _httpClientFactory.CreateClient();
            ////var response = await serverClient.GetAsync("https://localhost:44346/connect/authorize");
            //var serverResponse = await serverClient.PostAsync(AuthenticationUrl, usercontent2);

            //if (serverResponse.StatusCode == System.Net.HttpStatusCode.OK)
            //{
            //    var data = await serverResponse.Content.ReadAsStringAsync();
            //    AbpLoginResult xx = JsonConvert.DeserializeObject(data) as AbpLoginResult;
            //}

            return Ok(new
            {
                //message = usercontent2,
                //respones = serverResponse.Content
            }) ;
        }
    }
}
