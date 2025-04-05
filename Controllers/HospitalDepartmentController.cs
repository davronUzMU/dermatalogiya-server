using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HospitalDepartmentController : ControllerBase
    {
        private readonly HospitalDepartmentService _hospitalDepartmentService;
        public HospitalDepartmentController(HospitalDepartmentService hospitalDepartmentService)
        {
            _hospitalDepartmentService = hospitalDepartmentService;
        }
        [HttpGet]
        public IActionResult GetHospitalDepartments()
        {
            try
            {
                var result = _hospitalDepartmentService.GetHospitalDepartments();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost]
        [Authorize]
        public IActionResult PostHospitalDepartments([FromBody]HospitalDepartmentRequestDTO hospitalDepartmentRequestDTO)
        {
            try
            {
                var result = _hospitalDepartmentService.AddHospitalDepartments(hospitalDepartmentRequestDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPut("{Id}")]
        [Authorize]
        public IActionResult actionResult([FromBody]HospitalDepartmentRequestDTO hospitalDepartmentRequestDTO, int Id)
        {
            try
            {
                var result = _hospitalDepartmentService.EditHospitalDepartments(hospitalDepartmentRequestDTO, Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpDelete("{Id}")]
        [Authorize]
        public IActionResult DeleteHospitalDepartments(int Id)
        {
            try
            {
                var result = _hospitalDepartmentService.DeleteHospitalDepartments(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
