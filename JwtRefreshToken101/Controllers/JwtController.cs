using JwtRefreshToken101.Models;
using JwtRefreshToken101.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JwtRefreshToken101.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JwtController : ControllerBase
    {
        private readonly IJwtService _jwtservice;
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUserDbModel> _usermanager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public JwtController(IJwtService jwtservice, IConfiguration configuration,
            UserManager<ApplicationUserDbModel> usermanager, RoleManager<IdentityRole> roleManager)
        {
            _jwtservice = jwtservice;
            _configuration = configuration;
            _usermanager=usermanager;
            _roleManager=roleManager;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(LoginModel login)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = await _usermanager.FindByNameAsync(login.Username);
            if (user != null && await _usermanager.CheckPasswordAsync(user, login.Password)) {

                var roles = await _usermanager.GetRolesAsync(user);
                var authclaim = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Email, user.Email),

                };
                foreach(var userrole in roles)
                {
                    authclaim.Add(new Claim(ClaimTypes.Role, userrole));
                }

                _ = int.TryParse(_configuration["Jwt:AccessTokenValidityInSeconds"], out int AccessTokenValidityInSeconds);
                _ = int.TryParse(_configuration["Jwt:RefreshTokenValidyInMinutes"], out int RefreshTokenValidyInMinutes);
                var token = _jwtservice.CreateToken(authclaim);
                var refreshToken = _jwtservice.RefreshToken();
                user.AccessToken = new JwtSecurityTokenHandler().WriteToken(token);
                user.RefreshToken= refreshToken;
                user.AccessTokenExpires = DateTime.UtcNow.AddSeconds(AccessTokenValidityInSeconds);
                user.RefreshTokenExpires= DateTime.UtcNow.AddMinutes(RefreshTokenValidyInMinutes);
                await _usermanager.UpdateAsync(user);

                return Ok(new TokenResponse
                {
                    AccessToken= new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken= refreshToken,
                    AccessTokeExpires= token.ValidTo
                });

            }

            return Unauthorized(new AuthResponse { Status= "Failed " ,Message="Wrong Credentials"});
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin(RegisterModel registerModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = await _usermanager.FindByNameAsync(registerModel.Username);
            if (user != null)
            {
                return BadRequest(new AuthResponse { Status = "Failed", Message = "Username already exists" });
            }

            ApplicationUserDbModel appuser = new ApplicationUserDbModel()
            {
                UserName = registerModel.Username,
                SecurityStamp = Guid.NewGuid().ToString(),
                Email = registerModel.Email,
            };
            var createuser = await _usermanager.CreateAsync(appuser, registerModel.Password);
            if(!createuser.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new AuthResponse { Status = "Failed", Message = "Admin creation failed" });
            }
            if(!await _roleManager.RoleExistsAsync(UserRole.Admin))
            {
                var createrole= await _roleManager.CreateAsync(new IdentityRole(UserRole.Admin));
                if(!createrole.Succeeded) {
                    return StatusCode(StatusCodes.Status500InternalServerError, 
                        new AuthResponse { Status = "Failed", Message = "role creation failed" });
                }
                
            }
            var newadminrole = await _usermanager.AddToRoleAsync(appuser, UserRole.Admin);
            if(!newadminrole.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new AuthResponse { Status = "Failed", Message = "adding user to role failed" });
            }
            return Ok(new AuthResponse
            {
                Status = "Success",
                Message = "Admin-user created successfully"
            });
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("register-user")]
        public async Task<IActionResult> RegisterUser(RegisterModel registerModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = await _usermanager.FindByNameAsync(registerModel.Username);
            if (user != null)
            {
                return BadRequest(new AuthResponse { Status = "Failed", Message = "Username already exists" });
            }

            ApplicationUserDbModel appuser = new ApplicationUserDbModel()
            {
                UserName = registerModel.Username,
                SecurityStamp = Guid.NewGuid().ToString(),
                Email = registerModel.Email,
            };
            var createuser = await _usermanager.CreateAsync(appuser, registerModel.Password);
            if (!createuser.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new AuthResponse { Status = "Failed", Message = "User creation failed" });
            }
            if (!await _roleManager.RoleExistsAsync(UserRole.User))
            {
                var createrole = await _roleManager.CreateAsync(new IdentityRole(UserRole.User));
                if (!createrole.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new AuthResponse { Status = "Failed", Message = "role creation failed" });
                }

            }
            var newadminrole = await _usermanager.AddToRoleAsync(appuser, UserRole.User);
            if (!newadminrole.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new AuthResponse { Status = "Failed", Message = "adding user to role failed" });
            }
            return Ok(new AuthResponse
            {
                Status = "Success",
                Message = "User created successfully"
            });
        }

        [HttpPost]
        [Route("RefreshTokenRequest")]
        public async Task<IActionResult> RefreshTokenRequest(RefreshModel refreshModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var expiredaccessToken = refreshModel.ExpAccessToken;
            var refreshToken = refreshModel.RefreshToken;

            var principal = _jwtservice.GetPrincipalFromExpiredToken(expiredaccessToken);
            if (principal == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
            var user = principal!.Identity!.Name;
            var username= await _usermanager.FindByNameAsync(user);
            if (username == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, 
                    new AuthResponse { Status = "Failed", Message = "Wrong Expired AccessToken credentials" });
            }
            if(username.AccessTokenExpires >  DateTime.UtcNow)
            {
                return BadRequest(new AuthResponse { Status = "Failed", Message = "AccessToken not Expired" });
            }
            if (username.RefreshTokenExpires < DateTime.UtcNow)
            {
                return BadRequest(new AuthResponse { Status = "Failed", Message = "RefreshToken Expired" });
            }
            if (username.RefreshToken !=refreshToken)
            {
                return BadRequest(new AuthResponse { Status = "Failed", Message = "RefreshToken mismatch" });
            }



            _ = int.TryParse(_configuration["Jwt:AccessTokenValidityInSeconds"], out int AccessTokenValidityInSeconds);
            var newToken = _jwtservice.CreateToken(principal.Claims.ToList());
            var refreshT = _jwtservice.RefreshToken();
            username.AccessToken= new JwtSecurityTokenHandler().WriteToken(newToken);
            username.RefreshToken= refreshT;
            username.AccessTokenExpires= DateTime.UtcNow.AddSeconds(AccessTokenValidityInSeconds);

            await _usermanager.UpdateAsync(username);

            return Ok(new TokenResponse
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(newToken),
                RefreshToken = refreshT,
                AccessTokeExpires = newToken.ValidTo
            });


        }

        [Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme,Roles ="Admin")]
        [HttpPost]
        [Route("revoke-user")]
        public async Task<IActionResult> Revoke(string username)
        {
            var user= await _usermanager.FindByNameAsync(username);
            if (user != null)
            {
                user.AccessToken = null!;
                user.RefreshToken = null!;
                await _usermanager.UpdateAsync(user);
            }

            return BadRequest(new AuthResponse { Status = "Failed", Message = "Username does not exist" });
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            var users = await _usermanager.Users.ToListAsync();
           foreach(var userwithToken in users)
            {
                userwithToken.AccessToken = null!;
                userwithToken.RefreshToken = null!;
                await _usermanager.UpdateAsync(userwithToken);
            }

            return StatusCode(StatusCodes.Status500InternalServerError, 
                new AuthResponse { Status = "Failed", Message = $"Something went wrong in {nameof(RevokeAll)}" });
        }

    }
}
