using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class VideoController : ControllerBase
    {
        private readonly IVideoService _videoService;
        public VideoController(IVideoService videoService)
        {
            _videoService = videoService;
        }
        [HttpPost("upload")]
        [RequestSizeLimit(200 * 1024 * 1024)] // 100MB limit
        [RequestFormLimits(MultipartBodyLengthLimit = 200 * 1024 * 1024)]
        public async Task<IActionResult> UploadVideo([FromForm] VideoRequestDTO request)
        {
            try
            {
                var video = await _videoService.UploadVideoAsync(request);
                return CreatedAtAction(nameof(GetById), new { id = video.Id }, video);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetAll() => Ok(await _videoService.GetAllVideosAsync());

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            var video = await _videoService.GetVideoByIdAsync(id);
            if (video == null)
                return NotFound();

            var fullHlsUrl = $"{Request.Scheme}://{Request.Host}{video.HlsUrl}";
            return Ok(new { id = video.Id, description = video.Description, hlsUrl = fullHlsUrl });

            //var video = await _videoService.GetVideoByIdAsync(id);
            //return video == null ? NotFound() : Ok(video);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id)
            => await _videoService.DeleteVideoAsync(id) ? Ok() : NotFound();
    }
}
