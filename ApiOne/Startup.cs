using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace ApiOne
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication("Bearer")
                .AddJwtBearer("Bearer", config =>
                {
                    config.Authority = "https://localhost:44346/";
                    config.Audience = "ApiOne";
                    config.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false
                    };
                });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("ApiScope", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    policy.RequireClaim("scope", "ApiOne");
                });
                //options.AddPolicy("ERP.Class.Select", policy =>
                //    policy.RequireRole("ERP.Class.Select"));
                options.AddPolicy("ERP.Class.Select", policy => policy.RequireClaim("Class", "Select"));
                options.AddPolicy("ERP.Class.Insert", policy => policy.RequireClaim("Class", "Insert"));
                options.AddPolicy("ERP.Class.Update", policy => policy.RequireClaim("Class", "Update"));
                options.AddPolicy("ERP.Class.Delete", policy => policy.RequireClaim("Class", "Delete"));
            });

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
                endpoints.MapControllers()
                    .RequireAuthorization("ApiScope");
            });
        }
    }
}
