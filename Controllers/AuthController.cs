using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Vuln.Models;
using Vuln.Services;

namespace Vuln.Controllers
{
    [ApiController]
    [Route("auth")]
    public class AuthController : ControllerBase
    {
        readonly JwtSettings _jwtSettings;
        readonly UserService _userService;

        public AuthController(IOptions<JwtSettings> jwtSettings, UserService userService)
        {
            _jwtSettings = jwtSettings.Value;
            _userService = userService;
        }

        // TODO: specify responses for openapi docs
        [HttpPost("token")]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [AllowAnonymous]
        public IActionResult GenerateToken([FromBody] Login login)
        {
            if (ValidateCredentials(login, out User? user))
            {
                List<Claim> claims = [];
                if (user != null)
                {
                    foreach (var role in user.Roles)
                    {
                        claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
                    }
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
                    Console.WriteLine($"Could not generate token: {e.Message}");
                    return StatusCode(500);
                }
            }

            return Unauthorized();
        }

        private bool ValidateCredentials(Login login, out User? user)
        {
            user = _userService.GetUser(login.Username, login.Password);
            if (user != null)
            {
                return true;
            }

            return false;
        }
    }
}