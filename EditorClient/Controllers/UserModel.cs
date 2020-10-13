using System.IdentityModel.Tokens.Jwt;

namespace EditorClient.Controllers
{
    public partial class HomeController
    {
        public class UserModel
        {
            public string Username { get; set; }
            public string AccessToken { get; set; }
            public string RefreshToken { get; set; }
            public JwtSecurityToken DecodedAccessToken { get; set; }
        }
    }
}
