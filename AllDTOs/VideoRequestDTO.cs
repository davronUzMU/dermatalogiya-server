namespace Dermatologiya.Server.AllDTOs
{
    public class VideoRequestDTO
    {
        public string Description { get; set; } = string.Empty; // Video haqida ma'lumot
        public IFormFile VideoFile { get; set; } = null!; // Yuklanayotgan video fayli
    }
}
