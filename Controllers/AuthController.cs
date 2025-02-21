using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Vuln.Enums;
using Vuln.Models;

namespace Vuln.Controllers
{
    public class UserCredentials
    {
        required public ApplicationUser User { get; set; }
        public List<UserRole> Roles { get; set; } = [];
    }

    [ApiController]
    [Route("auth")]
    public class AuthController : ControllerBase
    {
        private readonly ILogger<AuthController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        readonly JwtSettings _jwtSettings;

        public AuthController(IOptions<JwtSettings> jwtSettings, UserManager<ApplicationUser> userManager, ILogger<AuthController> logger)
        {
            _jwtSettings = jwtSettings.Value;
            _logger = logger;
            _userManager = userManager;
        }

        // TODO: specify responses for openapi docs
        [HttpPost("token")]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [AllowAnonymous]
        public async Task<IActionResult> GenerateToken([FromBody] LoginModel login)
        {
            UserCredentials? credentials = await GetCredentials(login);
            _logger.LogDebug($"User {login.Username} is trying to login. Credentials:{credentials}");
            if (credentials != null)
            {
                List<Claim> claims = [];

                foreach (var role in credentials.Roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
                }

                // TODO: load key from configurations
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: "https://vuln.notrev.net",
                    audience: "https://vuln.notrev.net",
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds
                );

                try
                {
                    return Ok(new
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(token)
                    });
                }
                catch (ArgumentOutOfRangeException e)
                {
                    _logger.LogError($"Could not generate token: {e.Message}");
                    return StatusCode(500);
                }
            }

            return Unauthorized();
        }

        private async Task<UserCredentials?> GetCredentials(LoginModel login)
        {
            try
            {
                // Get and validate user
                var user = await _userManager.FindByNameAsync(login.Username);
                if (user == null)
                {
                    return null;
                }

                bool isPasswordValid = await _userManager.CheckPasswordAsync(user, login.Password);
                if (isPasswordValid == false)
                {
                    return null;
                }

                // Get roles
                List<UserRole> roles = [];
                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var userRole in userRoles)
                {
                    if (Enum.TryParse(userRole, out UserRole role))
                    {
                        roles.Add(role);
                    }
                }

                return new UserCredentials
                {
                    User = user,
                    Roles = roles
                };
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error when getting user credentials: {ex.Message}");
            }

            return null;
        }
    }
}