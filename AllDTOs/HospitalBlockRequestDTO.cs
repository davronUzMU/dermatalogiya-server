using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.AllDTOs
{
    public class HospitalBlockRequestDTO
    {
        [Required(ErrorMessage ="Block nomi bo'lishi shart")]
        [MaxLength(55, ErrorMessage = "Block nomi 55 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Block nomi 3 ta belgidan kam bo'lmasligi kerak")]
        public string BlockNameUz { get; set; } = string.Empty;

        [Required(ErrorMessage = "Block nomi bo'lishi shart")]
        [MaxLength(55, ErrorMessage = "Block nomi 55 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Block nomi 3 ta belgidan kam bo'lmasligi kerak")]
        public string BlockNameRu { get; set; } = string.Empty;

        [Required(ErrorMessage = "Block nomi bo'lishi shart")]
        [MaxLength(55, ErrorMessage = "Block nomi 55 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Block nomi 3 ta belgidan kam bo'lmasligi kerak")]
        public string BlockNameEn { get; set; } = string.Empty;

        public int ImageId { get; set; }
        public int VideoId { get; set; }


        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string HighTextUz { get; set; } = string.Empty;

        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string HighTextRu { get; set; } = string.Empty;

        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string HighTextEn { get; set; } = string.Empty;


        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string MiddleTextUz { get; set; } = string.Empty;
        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string MiddleTextRu { get; set; } = string.Empty;
        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string MiddleTextEn { get; set; } = string.Empty;


        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string LowTextUz { get; set; } = string.Empty;

        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string LowTextRu { get; set; } = string.Empty;

        [MaxLength(150, ErrorMessage = "Matn 150 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Matn 3 ta belgidan kam bo'lmasligi kerak")]
        public string LowTextEn { get; set; } = string.Empty;
    }
}
