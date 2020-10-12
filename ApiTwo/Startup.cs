using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ApiTwo
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication("Bearer")
                //.AddOpenIdConnect("oidc", config =>
                //{
                //    config.Authority = "https://localhost:44346/";
                //    config.ClientId = "Authentication_App";
                //    config.ClientSecret = "client_secret";
                //    config.SaveTokens = true;
                //    config.ResponseType = "password";

                //    // configure cookie claim mapping
                //    //config.ClaimActions.MapUniqueJsonKey("Brinox.Grandma", "rc.grandma");

                //    // two trips to load claims in the cookie
                //    // but the id cookie is smaller
                //    config.GetClaimsFromUserInfoEndpoint = true;

                //    // configure scope
                //    //config.Scope.Clear();
                //    config.Scope.Add("rc.scope");
                //    config.Scope.Add("openid");
                //    config.Scope.Add("ApiOne");
                //    config.Scope.Add("ApiTwo");
                //    //config.Scope.Add("offline_access");
                //})
                .AddJwtBearer("Bearer", config =>
                {
                    config.Authority = "https://localhost:44346/";
                    config.Audience = "ApiTwo";
                    //config.TokenValidationParameters = new TokenValidationParameters
                    //{
                    //    ValidateIssuer = false,
                    //    ValidateAudience = false
                    //};

                });
                 

            services.AddHttpClient();

            services.AddControllers();
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
                endpoints.MapControllers();
            });
        }
    }
}
