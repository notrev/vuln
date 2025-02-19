using Vuln.Enums;

namespace Vuln.Models
{
    public class User
    {
        required public string Username { get; set; }
        required public string Password { get; set; }
        public List<UserRole> Roles { get; set; } = [];
    }
}