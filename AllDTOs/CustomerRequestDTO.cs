using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.AllDTOs
{
    public class CustomerRequestDTO
    {
        [Required(ErrorMessage ="F.I.O  kiritish majburiy")]
        [MaxLength(50, ErrorMessage = "F.I.O 50 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "F.I.O 3 ta belgidan kam bo'lish kerak emas")]
        public string FullName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Telefon raqam kiritish majburiy")]
        [MaxLength(13, ErrorMessage = "Telefon raqam 13 ta belgidan oshmasligi kerak")]
        [MinLength(9, ErrorMessage = "Telefon raqam 9 ta belgidan kam bo'lishi kerak emas")]
        public string PhoneNumber { get; set; } = string.Empty;

        public string Description { get; set; } = string.Empty;
    }
}
