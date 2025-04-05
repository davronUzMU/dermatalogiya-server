using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class QueueController : ControllerBase
    {
        private readonly QueueService _queueService;
        public QueueController(QueueService queueService)
        {
            _queueService = queueService;
        }
        [HttpGet]
        public IActionResult GetQueue()
        {
            try
            {
                var result = _queueService.GetAllQueue();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost]
        [Authorize]
        public IActionResult PostQueue(QueueRequestDTO queueRequestDTO)
        {
            try
            {
                var result = _queueService.AddQueue(queueRequestDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPut("{Id}")]
        [Authorize]
        public IActionResult actionResultQueue(QueueRequestDTO queueRequestDTO, int Id)
        {
            try
            {
                var result = _queueService.EditQueue(queueRequestDTO, Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpDelete("{Id}")]
        [Authorize]
        public IActionResult DeleteQueue(int Id)
        {
            try
            {
                var result = _queueService.DeleteQueue(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
