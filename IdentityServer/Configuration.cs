using IdentityModel;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace IdentityServer
{
    public static class Configuration
    {
        public static IEnumerable<IdentityResource> GetIdentityResources() =>
            new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResource
                {
                    Name = "rc.scope",
                    UserClaims =
                    {
                        "rc.grandma",
                    }
                }
            };

        public static IEnumerable<ApiResource> GetApis() =>
            new List<ApiResource> {
                new ApiResource("ApiOne", new string[] {"rc.api.grandma"}),
                new ApiResource("ApiTwo"),
            };

        public static IEnumerable<Client> GetClients() =>
            new List<Client> {
                new Client
                {
                    ClientId = "client_id",
                    ClientSecrets = { new Secret("client_secret".ToSha256()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes = {"ApiOne"}
                },
                 new Client
                {
                    ClientId = "client_id_mvc",
                    ClientSecrets = { new Secret("client_secret_mvc".ToSha256()) },
                    AllowedGrantTypes = GrantTypes.Code,
                    RedirectUris = {"https://localhost:44315/signin-oidc" },
                    AllowedScopes = {
                            "ApiOne",
                            "ApiTwo",
                            "rc.scope",
                            IdentityServer4.IdentityServerConstants.StandardScopes.OpenId,
                            IdentityServer4.IdentityServerConstants.StandardScopes.Profile,
                            },
                    RequireConsent = false,
                    // puts all the claims in the id token
                    //AlwaysIncludeUserClaimsInIdToken = true,
                    }
            };

        public static IEnumerable<ApiScope> GetApiScopes() => new List<ApiScope> { new ApiScope("ApiOne") };

    }
}
