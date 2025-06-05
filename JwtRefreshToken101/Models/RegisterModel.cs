using System.ComponentModel.DataAnnotations;

namespace JwtRefreshToken101.Models
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "Username required")]
        public string? Username {  get; set; }

        [Required(ErrorMessage = "Email required")]
        [EmailAddress]
        public string Email { get; set;} = string.Empty;

        [Required(ErrorMessage = "Password required")]
        public string? Password { get; set; } = string.Empty;

    }
}
