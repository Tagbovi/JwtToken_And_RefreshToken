using JwtRefreshToken101.Data;
using JwtRefreshToken101.Models;
using JwtRefreshToken101.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JwtRefreshToken101.ServiceExtension
{
    public static class ServiceConfigurations
    {
        public static void RegisterJwtService(this IServiceCollection services)
        {
            services.AddScoped<IJwtService, JwtService>();
        }
        public static void RegisterConnectionstringService(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<JwtDbContext>(opt => opt.UseNpgsql(configuration.GetConnectionString("Default")));
        }

        public static void RegisterUserIdentity(this IServiceCollection services)
        {
            services.AddIdentity<ApplicationUserDbModel, IdentityRole>()
                .AddEntityFrameworkStores<JwtDbContext>().AddDefaultTokenProviders();
        }

        public static void RegisterAuthenticationService(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(opt=>
            {
                opt.DefaultAuthenticateScheme=JwtBearerDefaults.AuthenticationScheme;
                opt.DefaultChallengeScheme=JwtBearerDefaults.AuthenticationScheme;
                opt.DefaultScheme= JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(opt =>
            {
                opt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidAudience = configuration["Jwt:ValidAudience"],
                    ValidIssuer = configuration["Jwt:ValidIssuer"],
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["Jwt:Key"])),
                   ClockSkew=TimeSpan.Zero

                };
            });
        }

    }
}
