using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.Models
{
    public class News
    {
        [Key]
        public int Id { get; set; }
        public string newType { get; set; } = string.Empty; // Yangilik turi
        public string TitleUz { get; set; } = string.Empty; // Yangilik sarlavhasi
        public string TitleRu { get; set; } = string.Empty; // Yangilik sarlavhasi
        public string TitleEn { get; set; } = string.Empty; // Yangilik sarlavhasi
        public string ContentUz { get; set; } = string.Empty; // Yangilik matni
        public string ContentRu { get; set; } = string.Empty; // Yangilik matni
        public string ContentEn { get; set; } = string.Empty; // Yangilik matni
        public int ImageUrl { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
