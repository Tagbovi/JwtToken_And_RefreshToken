using Microsoft.AspNetCore.Identity;

namespace JwtRefreshToken101.Models
{
    public class ApplicationUserDbModel : IdentityUser
    {
      
        public string AccessToken { get; set; } = string.Empty;
        public DateTime AccessTokenExpires { get; set; }
        public string RefreshToken { get; set; }= string.Empty;
        public DateTime RefreshTokenExpires { get; set; }

    }
}
