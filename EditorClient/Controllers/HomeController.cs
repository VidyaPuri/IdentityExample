using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Volo.Abp.Identity;
using Volo.Abp.Modularity;
using Newtonsoft.Json.Linq;

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
            var token = Request.Headers["code"];

            // retrieve access token
            var serverClient = _httpClientFactory.CreateClient();
            var acToken = await HttpContext.GetTokenAsync("access_token");
            var idToken = await HttpContext.GetTokenAsync("id_token");

            var _idToken = new JwtSecurityTokenHandler().ReadJwtToken(idToken);
            var _acToken = new JwtSecurityTokenHandler().ReadJwtToken(acToken);

            var discoveryDocument = await serverClient.GetDiscoveryDocumentAsync("https://localhost:44346/");

            //string urlString = $"{discoveryDocument.AuthorizeEndpoint}?clientId='Authentication_Editor'&redirect_uri='https://localhost:44358/signin-oidc'&response_type='code'";
            //var asdf = await serverClient.GetAsync(urlString);

            //var ru = new RequestUrl("https://localhost:44346/");

            //var url = ru.CreateAuthorizeUrl(
            //    clientId: "Authentication_Editor",
            //    responseType: "code",
            //    redirectUri: "https://localhost:44358/signin-oidc",
            //    scope: "openid profile");

            //var sth = await serverClient.GetAsync(url);

            //var json = await sth.Content.ReadAsStringAsync();

            //var apiResponse = Newtonsoft.Json.JsonConvert.DeserializeObject(json);

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

            //var authToken = await serverClient.RequestAuthorizationCodeTokenAsync(
            //    new AuthorizationCodeTokenRequest
            //    {
            //        GrantType = "authorization_code",
            //        Address = discoveryDocument.TokenEndpoint,
            //        ClientId = "Authentication_Editor",
            //        ClientSecret = "editor_secret",
            //        Code = accessToken123,
            //        RedirectUri = "https://localhost:44358/signin-oidc"
            //    });

            UserInfoResponse userInfo = await serverClient.GetUserInfoAsync(
                new UserInfoRequest
                {
                    Address = discoveryDocument.UserInfoEndpoint,
                    Token = responseToken.AccessToken
                });

            User.AccessToken = responseToken.AccessToken;
            User.RefreshToken = responseToken.RefreshToken;

            var _accessToken = new JwtSecurityTokenHandler().ReadJwtToken(User.AccessToken);
            var infoClaims = userInfo.Claims;
            var claims = _accessToken.Claims;
            var userId = claims.SingleOrDefault(x => x.Type == "sub").Value;



            // retrieve secret data
            var apiClient = _httpClientFactory.CreateClient();

            apiClient.SetBearerToken(User.AccessToken);
            var user = await apiClient.GetAsync($"https://localhost:44346/api/identity/users/{userId}");


            //var response = await apiClient.GetAsync("https://localhost:44308/secret");

            //if (response.Headers.Contains("token-expired") && response.Headers.GetValues("Token-Expired").FirstOrDefault().ToLower().Trim() == "true")
            //{
            //    // Token expired - login with refresh token and retry request
            //    await RefreshAccessToken(User.RefreshToken);

            //    apiClient.SetBearerToken(User.AccessToken);
            //    //response = await apiClient.GetAsync("https://localhost:44308/secret");
            //}

            //var content = await response.Content.ReadAsStringAsync();


            //response = await apiClient.GetAsync("https://localhost:44308/secret");
            //content = await response.Content.ReadAsStringAsync();

            return Ok(new
            {
                data = user,
            });
        }

        [Route("/secret")]
        public async Task<IActionResult> Secret()
        {
            var accessToken123 = await HttpContext.GetTokenAsync("access_token");
            var idToken123 = await HttpContext.GetTokenAsync("id_token");

            return Ok();
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


        /// <summary>
        /// Getting refresh token
        /// </summary>
        /// <returns></returns>
        private async Task RefreshAccessToken(string refreshToken)
        {
            var serverClient = _httpClientFactory.CreateClient();
            var discoveryDocument = await serverClient.GetDiscoveryDocumentAsync("https://localhost:44346/");

            var refreshTokenClient = _httpClientFactory.CreateClient();

            var tokenResponse = await refreshTokenClient.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                RefreshToken = refreshToken,
                Address = discoveryDocument.TokenEndpoint,
                ClientId = "Authentication_Editor",
                ClientSecret = "editor_secret"
            });

            User.AccessToken = tokenResponse.AccessToken;
            User.RefreshToken = tokenResponse.RefreshToken;

            //var authInfo = await HttpContext.AuthenticateAsync("Cookie");

            //authInfo.Properties.UpdateTokenValue("access_token", tokenResponse.AccessToken);
            //authInfo.Properties.UpdateTokenValue("refresh_token", tokenResponse.RefreshToken);

            //await HttpContext.SignInAsync("Cookie", authInfo.Principal, authInfo.Properties);
        }
    }
}
