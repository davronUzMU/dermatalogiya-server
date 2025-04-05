using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HospitalBlockController : ControllerBase
    {
        private readonly HospitalBlockService _hospitalBlockService;
        public HospitalBlockController(HospitalBlockService hospitalBlockService)
        {
            _hospitalBlockService = hospitalBlockService;
        }
        [HttpGet]
        public IActionResult GetHospitalBlocks()
        {
            try
            {
                var result = _hospitalBlockService.GetHospitalBlocks();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpGet("{Id}")]
        public IActionResult GetHospitalBlocksById(int Id)
        {
            try
            {
                var result = _hospitalBlockService.GetHospitalBlocksById(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost]
        [Authorize]
        public IActionResult PostHospitalBlocks(HospitalBlockRequestDTO hospitalBlockRequestDTO)
        {
            try
            {
                var result = _hospitalBlockService.AddHospitalBlocks(hospitalBlockRequestDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPut("{Id}")]
        [Authorize]
        public IActionResult actionResult(HospitalBlockRequestDTO hospitalBlockRequestDTO, int Id)
        {
            try
            {
                var result = _hospitalBlockService.EditHospitalBlocks(hospitalBlockRequestDTO, Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpDelete("{Id}")]
        [Authorize]
        public IActionResult DeleteHospitalBlocks(int Id)
        {
            try
            {
                var result = _hospitalBlockService.DeleteHospitalBlocks(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
