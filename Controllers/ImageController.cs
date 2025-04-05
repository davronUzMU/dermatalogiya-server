using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dermatologiya.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ImageController : ControllerBase
    {
        private readonly IImageService _imageService;
        public ImageController(IImageService imageService)
        {
            _imageService = imageService;
        }
        [HttpPost("upload")]
        //[Authorize]
        public async Task<IActionResult> UploadImage(IFormFile file)
        {
            try
            {
                var result =await _imageService.UploadImage(file);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }

        }
        [HttpGet("all")]
        public async Task<IActionResult> GetAllImages()
        {
            try
            {
                var images = await _imageService.GetAll();
                return Ok(images);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("{Id}")]
        public async Task<IActionResult> GetImageById(int Id)
        {
            try
            {
                var result = await _imageService.GetImageById(Id);
                if (result == null)
                    return NotFound("Image not found");

                string res = GetContentType(result);

                return File(System.IO.File.ReadAllBytes(result), res);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpDelete("{Id}")]
        //[Authorize]
        public async Task<IActionResult> DeleteImage(int Id)
        {

            try
            {
                var result =await _imageService.DeleteById(Id);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        private string GetContentType(string path)
        {
            var ext = Path.GetExtension(path).ToLower();
            return ext switch
            {
                ".jpg" or ".jpeg" => "image/jpeg",
                ".png" => "image/png",
                ".gif" => "image/gif",
                ".bmp" => "image/bmp",
                ".svg" => "image/svg+xml",
                ".webp" => "image/webp",
                _ => "application/octet-stream"
            };
        }
    }
}
