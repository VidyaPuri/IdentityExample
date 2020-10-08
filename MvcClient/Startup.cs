using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace MvcClient
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(config => {
                config.DefaultScheme = "Cookie";
                config.DefaultChallengeScheme = "oidc";
            })
                .AddCookie("Cookie")
                .AddOpenIdConnect("oidc", config =>
                {
                    config.Authority = "https://localhost:44333/";
                    config.ClientId = "client_id_mvc";
                    config.ClientSecret = "client_secret_mvc";
                    config.SaveTokens = true;
                    config.ResponseType = "code";

                    // configure cookie claim mapping
                    config.ClaimActions.MapUniqueJsonKey("Brinox.Grandma", "rc.grandma");

                    // two trips to load claims in the cookie
                    // but the id cookie is smaller
                    config.GetClaimsFromUserInfoEndpoint = true;

                    // configure scope
                    //config.Scope.Clear();
                    config.Scope.Add("rc.scope");
                    config.Scope.Add("openid");
                    config.Scope.Add("ApiOne");
                    config.Scope.Add("ApiTwo");
                    config.Scope.Add("offline_access");
                });

            services.AddHttpClient();
            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
