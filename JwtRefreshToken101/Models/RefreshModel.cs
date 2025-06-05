using System.ComponentModel.DataAnnotations;

namespace JwtRefreshToken101.Models
{
    public class RefreshModel
    {
        [Required(ErrorMessage ="Expired token required")]
        public string ExpAccessToken { get; set; } = string.Empty;

        [Required(ErrorMessage ="RefreshToken required")]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
