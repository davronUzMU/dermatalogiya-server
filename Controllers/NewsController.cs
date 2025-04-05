using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class NewsController : ControllerBase
    {
        private readonly NewsService _newsService;
        public NewsController(NewsService newsService)
        {
            _newsService = newsService;
        }
        [HttpGet("tibbiyot-news")]
        public IActionResult GetAllNews()
        {
            try
            {
                var result = _newsService.GetAllNews();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpGet("tibbiyot-news/{Id}")]
        public IActionResult GetNewsById(int Id)
        {
            try
            {
                var result = _newsService.GetNewsById(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost("tibbiyot-news")]
        [Authorize]
        public IActionResult AddNews(NewsRequestDTO newsRequestDTO)
        {
            try
            {
                var result = _newsService.AddNews(newsRequestDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPut("tibbiyot-news/{id}")]
        [Authorize]
        public IActionResult EditNews(NewsRequestDTO newsRequestDTO, int id)
        {
            try
            {
                var result = _newsService.EditNews(newsRequestDTO, id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpDelete("tibbiyot-news/{Id}")]
        [Authorize]
        public IActionResult Delete(int id)
        {
            try
            {
                _newsService.DeleteNews(id);
                return Ok("Open data deleted");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }




        [HttpGet("elon-news")]
        public IActionResult GetAllElon()
        {
            try
            {
                var result = _newsService.GetAllElon();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpGet("elon-news/{Id}")]
        public IActionResult GetElonById(int Id)
        {
            try
            {
                var result = _newsService.GetElonById(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPost("elon-news")]
        [Authorize]
        public IActionResult AddElon(NewsRequestDTO newsRequestDTO)
        {
            try
            {
                var result = _newsService.AddElon(newsRequestDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpPut("elon-news/{id}")]
        [Authorize]
        public IActionResult EditElon(NewsRequestDTO newsRequestDTO, int id)
        {
            try
            {
                var result = _newsService.EditElon(newsRequestDTO, id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [HttpDelete("elon-news/{Id}")]
        [Authorize]
        public IActionResult DeleteElon(int id)
        {
            try
            {
                _newsService.DeleteElon(id);
                return Ok("Open data deleted");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
