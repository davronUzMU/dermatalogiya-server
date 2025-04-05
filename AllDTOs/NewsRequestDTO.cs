using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.AllDTOs
{
    public class NewsRequestDTO
    {
        [Required(ErrorMessage ="Sarlavha bo'sh bo'lishi mumkin emas")]
        [MaxLength(75, ErrorMessage = "Sarlavha 75 ta belgidan oshmasligi kerak")]
        [MinLength(5, ErrorMessage = "Sarlavha 5 ta belgidan kam bo'lishi kerak")]
        public string TitleUz { get; set; } = string.Empty; // Yangilik sarlavhasi


        [Required(ErrorMessage = "Sarlavha bo'sh bo'lishi mumkin emas")]
        [MaxLength(75, ErrorMessage = "Sarlavha 75 ta belgidan oshmasligi kerak")]
        [MinLength(5, ErrorMessage = "Sarlavha 5 ta belgidan kam bo'lishi kerak")]
        public string TitleRu { get; set; } = string.Empty; // Yangilik sarlavhasi


        [Required(ErrorMessage = "Sarlavha bo'sh bo'lishi mumkin emas")]
        [MaxLength(75, ErrorMessage = "Sarlavha 75 ta belgidan oshmasligi kerak")]
        [MinLength(5, ErrorMessage = "Sarlavha 5 ta belgidan kam bo'lishi kerak")]
        public string TitleEn { get; set; } = string.Empty; // Yangilik sarlavhasi

        [Required(ErrorMessage = "Matn bo'sh bo'lishi mumkin emas")]
        [MinLength(10, ErrorMessage = "Matn 10 ta belgidan kam bo'lishi mumkin emas")]
        [MaxLength(300, ErrorMessage = "Matn 300 ta belgidan oshmasligi kerak")]
        public string ContentUz { get; set; } = string.Empty; // Yangilik matni

        [Required(ErrorMessage = "Matn bo'sh bo'lishi mumkin emas")]
        [MinLength(10, ErrorMessage = "Matn 10 ta belgidan kam bo'lishi mumkin emas")]
        [MaxLength(300, ErrorMessage = "Matn 300 ta belgidan oshmasligi kerak")]
        public string ContentRu { get; set; } = string.Empty; // Yangilik matni

        [Required(ErrorMessage = "Matn bo'sh bo'lishi mumkin emas")]
        [MinLength(10, ErrorMessage = "Matn 10 ta belgidan kam bo'lishi mumkin emas")]
        [MaxLength(300, ErrorMessage = "Matn 300 ta belgidan oshmasligi kerak")]
        public string ContentEn { get; set; } = string.Empty; // Yangilik matni
        public int ImageUrl { get; set; }
    }
}
