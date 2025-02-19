using Vuln.Models;
using Vuln.Enums;
using System.Security.Cryptography;
using System.Text;

namespace Vuln.Services
{
    public class UserService
    {
        private readonly Dictionary<string, User> _users = [];
        private readonly SHA3_512 _sha3 = SHA3_512.Create();
        
        public UserService()
        {
            _users.Add("publisher", new User { Username = "publisher", Password = HashPassword("thisIsNotThePasswordYouAreLookingFor"), Roles = [UserRole.Writer] });
            _users.Add("reader", new User { Username = "reader", Password = HashPassword("iWontTellYou"), Roles = [UserRole.Reader] });
            _users.Add("root", new User { Username = "root", Password = HashPassword("yourCreditCardNumber"), Roles = [UserRole.Writer, UserRole.Reader] });
        }

        public User? GetUser(string username, string password)
        {
            string hashedPassword = HashPassword(password);
            if (_users.ContainsKey(username)) {
                if (_users[username].Password == hashedPassword) {
                    return _users[username];
                }
                return _users[username];
            }
            return null;
        }

        private string HashPassword(string password)
        {
            byte[] data = _sha3.ComputeHash(Encoding.UTF8.GetBytes(password));
            var sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }
            return sBuilder.ToString();
        }
    }
}