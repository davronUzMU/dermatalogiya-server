using Dermatologiya.Server.AllDTOs;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Dermatologiya.Server.Services
{
    public class JwtService
    {
        private readonly IConfiguration _configuration;
        private readonly string userName = "6o3r57w!-(D`z!]O";
        private readonly string password = "X@p%mc^AVc0Y%nuMtzF.leeO]&^k%6T,b18+P\\_K}nB8F11,h}";

        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateToken(LoginDTO model)
        {
            if (!model.Username.Equals(userName) && !model.Password.Equals(password))
            {
                throw new Exception("Username yoki parol noto'g'ri");
            }
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"];
            var issuer = jwtSettings["Issuer"];
            var audience = jwtSettings["Audience"];
            var tokenLifetime = int.Parse(jwtSettings["TokenLifetime"]); // 432000 soniya = 5 kun

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, model.Username),
                new Claim(ClaimTypes.Role, "Admin") // Faqat adminlar uchun
            };

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddSeconds(tokenLifetime),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public object Logout()
        {
            throw new NotImplementedException();
        }
    }
}
