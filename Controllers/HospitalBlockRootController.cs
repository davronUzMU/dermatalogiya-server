using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HospitalBlockRootController : ControllerBase
    {
        private readonly BlockRootService _hospitalBlockService;
        public HospitalBlockRootController(BlockRootService hospitalBlockService)
        {
            _hospitalBlockService = hospitalBlockService;
        }
        [HttpGet]
        public IActionResult GetHospitalBlocksRoot()
        {
            try
            {
                var result = _hospitalBlockService.GetHospitalBlocksRoot();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost]
        [Authorize]
        public IActionResult PostHospitalBlocksRoot(BlockRootRequestDTO blockRootRequestDTO)
        {
            try
            {
                var result = _hospitalBlockService.AddHospitalBlocksRoot(blockRootRequestDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPut("{Id}")]
        [Authorize]
        public IActionResult actionResultRoot(BlockRootRequestDTO blockRootRequestDTO, int Id)
        {
            try
            {
                var result = _hospitalBlockService.EditHospitalBlocksRoot(blockRootRequestDTO, Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpDelete("{Id}")]
        [Authorize]
        public IActionResult DeleteHospitalBlocksRoot(int Id)
        {
            try
            {
                var result = _hospitalBlockService.DeleteHospitalBlocksRoot(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
