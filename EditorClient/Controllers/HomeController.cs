using IdentityModel.Client;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Volo.Abp.Identity;
using Volo.Abp.Modularity;

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

            //var rspt = await serverClient.RequestTokenAsync(
            //    new TokenRequest
            //    {
            //        GrantType = "client_credentials",
            //        Address = discoveryDocument.TokenEndpoint,
            //        ClientId = "Authentication_Editor",
            //        ClientSecret = "editor_secret"
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
            //var infoClaims = userInfo.Claims;
            var claims = _accessToken.Claims;


            //var userAppService = GetRequiredService<IIdentityUserAppService>();

            var user = new ClaimsPrincipal();

            //var id = HttpContext.User.Identity;
            //profileAppService = new ProfileAppService();

            //var profileDto = await _profileAppService.GetAsync();


            // retrieve secret data
            var apiClient = _httpClientFactory.CreateClient();

            apiClient.SetBearerToken(User.AccessToken);

            var response = await apiClient.GetAsync("https://localhost:44308/secret");

            if (response.Headers.Contains("token-expired") && response.Headers.GetValues("Token-Expired").FirstOrDefault().ToLower().Trim() == "true")
            {
                // Token expired - login with refresh token and retry request
                await RefreshAccessToken(User.RefreshToken);

                apiClient.SetBearerToken(User.AccessToken);
                response = await apiClient.GetAsync("https://localhost:44308/secret");
            }

            var content = await response.Content.ReadAsStringAsync();


            return Ok(new
            {
                data = content,
            }) ;

        }

        [Route("/secret")]
        public async Task<IActionResult> Secret()
        {
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
