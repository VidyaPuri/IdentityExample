using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace EditorClient
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            //services.AddAuthentication(config =>
            //{
            //    config.DefaultScheme = "Cookie";
            //    config.DefaultChallengeScheme = "oidc";
            //})
            //.AddCookie("Cookie")
            //.AddOpenIdConnect("oidc", config =>
            //{
            //    config.Authority = "https://authentication.vsrt-ws.brinox.si/";
            //    config.ClientId = "Authentication_Editor";
            //    config.ClientSecret = "editor_secret";
            //    config.SaveTokens = true;
            //    config.ResponseType = "code";

            //    // configure scope
            //    config.Scope.Add("openid");
            //    config.Scope.Add("offline_access");
            //});
            services.AddAuthentication(IISDefaults.AuthenticationScheme);
            services.AddAuthorization(options =>
            {
                options.AddPolicy("ApiScope", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    //policy.RequireClaim("scope", "ApiOne");
                });
                //options.AddPolicy("ERP.Class.Select", policy =>
                //    policy.RequireRole("ERP.Class.Select"));
                options.AddPolicy("ERP.Class.Select", policy => policy.RequireClaim("Class", "Select"));
                options.AddPolicy("ERP.Class.Insert", policy => policy.RequireClaim("Class", "Insert"));
                options.AddPolicy("ERP.Class.Update", policy => policy.RequireClaim("Class", "Update"));
                options.AddPolicy("ERP.Class.Delete", policy => policy.RequireClaim("Class", "Delete"));
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
