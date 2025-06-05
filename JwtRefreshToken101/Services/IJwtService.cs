using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JwtRefreshToken101.Services
{
    public interface IJwtService
    {
       JwtSecurityToken CreateToken (List<Claim> authclaim);
        string RefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string expiredToken);
    }
}
