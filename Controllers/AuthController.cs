using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly JwtService _jwtService;
        public AuthController(JwtService jwtService)
        {
            _jwtService = jwtService;
        }
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginDTO model)
        {
            try
            {
                var token = _jwtService.GenerateToken(model);
                return Ok(new { Token = token });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpGet("logout")]
        public IActionResult Logout()
        {
            try
            {
                var token = _jwtService.Logout();
                return Ok(new { Token = token });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
