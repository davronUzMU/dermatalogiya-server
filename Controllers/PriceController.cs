using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PriceController : ControllerBase
    {
        private readonly PriceService _priceService;
        public PriceController(PriceService priceService)
        {
            _priceService = priceService;
        }
        [HttpGet]
        public IActionResult GetAllPrice()
        {
            try
            {
                var result = _priceService.GetAllPrice();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost]
        [Authorize]
        public IActionResult PostPrice(PriceRequestDTO priceRequestDTO)
        {
            try
            {
                var result = _priceService.AddPrice(priceRequestDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPut("{Id}")]
        [Authorize]
        public IActionResult actionPrice(PriceRequestDTO priceRequestDTO, int Id)
        {
            try
            {
                var result = _priceService.EditPrice(priceRequestDTO, Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpDelete("{Id}")]
        [Authorize]
        public IActionResult DeletePrice(int Id)
        {
            try
            {
                var result =_priceService.DeletePrice(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
