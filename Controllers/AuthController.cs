using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Vuln.Models;

namespace Vuln.Controllers
{
    [ApiController]
    [Route("auth")]
    public class AuthController : ControllerBase
    {
        readonly List<LoginModel> _credentials;
        readonly JwtSettings _jwtSettings;

        public AuthController(IOptions<JwtSettings> jwtSettings)
        {
            _credentials =
            [
                new LoginModel
                {
                    Username = "test",
                    Password = "password"
                },
                new LoginModel
                {
                    Username = "admin",
                    Password = "notAdminPassword"
                }
            ];

            _jwtSettings = jwtSettings.Value;
        }

        // TODO: specify responses for openapi docs
        [HttpPost("token")]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [AllowAnonymous]
        public IActionResult GenerateToken([FromBody] LoginModel login)
        {
            // Validate the user credentials
            // TODO: replace with validation logic
            if (ValidateCredentials(login))
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, login.Username)
                };

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
                    Console.WriteLine("Could not generate token: " + e.Message);
                    return StatusCode(500);
                }
            }

            return Unauthorized();
        }

        private bool ValidateCredentials(LoginModel login)
        {
            return _credentials.Any(c => c.Username == login.Username && c.Password == login.Password);
        }
    }
}