namespace Dermatologiya.Server.AllDTOs
{
    public class VideoResponseDTO
    {
        public int Id { get; set; }
        public string Description { get; set; } = string.Empty; // Video haqida ma'lumot
        public string HlsUrl { get; set; } = string.Empty; // HLS formatidagi video fayl manzili
    }
}
