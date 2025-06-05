using JwtRefreshToken101.Data;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtRefreshToken101.Services
{
    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly JwtDbContext _jwtDbContext;

        public JwtService(IConfiguration configuration, JwtDbContext jwtDbContext)
        {
            _configuration = configuration;
            _jwtDbContext = jwtDbContext;
        }
        public  JwtSecurityToken CreateToken(List<Claim> authclaim)
        {
            _ = int.TryParse(_configuration["Jwt:AccessTokenValidityInSeconds"], out int AccessTokenValidityInSeconds);
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]));
            var Token = new JwtSecurityToken(
                issuer: _configuration["Jwt:ValidIssuer"],
                audience: _configuration["Jwt:ValidAudience"],
                claims: authclaim,
                expires: DateTime.UtcNow.AddSeconds(AccessTokenValidityInSeconds),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
                );

            return  Token;
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string expiredToken)
        {
            var jwtSecurityToken = new JwtSecurityTokenHandler();
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]));
            TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
            {

                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,

            };

           var principal=jwtSecurityToken.ValidateToken(expiredToken, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken1 || !jwtSecurityToken1.Header.Alg.Equals(SecurityAlgorithms.
                HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid Credentials");


            return principal;
        }

        public string RefreshToken()
        {
            var bytecodes= new byte[32];
            using(var rnd= RandomNumberGenerator.Create())
            {
                rnd.GetBytes(bytecodes);
                return Convert.ToBase64String(bytecodes);
            }
        }
    }
}
