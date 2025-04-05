using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.Models
{
    public class VideoForCustomer
    {
        [Key]
        public int Id { get; set; }
        public string Description { get; set; } = string.Empty; // Video haqida ma'lumot
        public string Title { get; set; } = string.Empty; // Video nomi      
        public string OriginalFileUrl { get; set; } = string.Empty; // Asl yuklangan fayl
        public string HlsUrl { get; set; } = string.Empty; // HLS formatidagi m3u8 fayl manzili
        public int ThumbnailId { get; set; } // Video preview rasmi
        public DateTime UploadedAt { get; set; } // Yuklangan vaqt
    }
}
