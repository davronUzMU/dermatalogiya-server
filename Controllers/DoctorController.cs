using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DoctorController : ControllerBase
    {
        private readonly DoctorService _doctorService;
        public DoctorController(DoctorService doctorService)
        {
            _doctorService = doctorService;
        }
        [HttpGet]
        public IActionResult GerDoctors()
        {
            try
            {
                var result = _doctorService.GetDoctors();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpGet("{Id}")]
        public IActionResult GetDoctorsById(int Id)
        {
            try
            {
                var result = _doctorService.GetDoctorsById(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost]
        [Authorize]
        public IActionResult PostDoctors(DoctorRequestDTO doctorRequestDTO)
        {
            try
            {
                var result = _doctorService.AddDoctors(doctorRequestDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPut("{Id}")]
        [Authorize]
        public IActionResult actionResult(DoctorRequestDTO doctorRequestDTO, int Id)
        {
            try
            {
                var result = _doctorService.EditDoctors(doctorRequestDTO, Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpDelete("{Id}")]
        [Authorize]
        public IActionResult DeleteDoctors(int Id)
        {
            try
            {
                var result = _doctorService.DeleteDoctors(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
