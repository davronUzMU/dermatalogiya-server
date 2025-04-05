using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.AllDTOs
{
    public class PriceRequestDTO
    {
        [Required(ErrorMessage = "nomi bo'lishi shart")]
        [MaxLength(100,ErrorMessage ="Belgilar soni 100 oshib ketishi mumkin emas")]
        [MinLength(3, ErrorMessage = "Belgilar soni 3 dan kam bo'lishi mumkin emas")]
        public string ServiceNameUz { get; set; } = string.Empty;

        [Required(ErrorMessage = "nomi bo'lishi shart")]
        [MaxLength(100, ErrorMessage = "Belgilar soni 100 oshib ketishi mumkin emas")]
        [MinLength(3, ErrorMessage = "Belgilar soni 3 dan kam bo'lishi mumkin emas")]
        public string ServiceNameRu { get; set; } = string.Empty;

        [Required(ErrorMessage = "nomi bo'lishi shart")]
        [MaxLength(100, ErrorMessage = "Belgilar soni 100 oshib ketishi mumkin emas")]
        [MinLength(3, ErrorMessage = "Belgilar soni 3 dan kam bo'lishi mumkin emas")]
        public string ServiceNameEn { get; set; } = string.Empty;
        public double Price { get; set; }
    }
}
