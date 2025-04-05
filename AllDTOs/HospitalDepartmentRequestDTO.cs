using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.AllDTOs
{
    public class HospitalDepartmentRequestDTO
    {
        [Required(ErrorMessage ="Bo'lim bo'lishi shart")]
        [MaxLength(50, ErrorMessage = "Bo'lim nomi 50 ta harfdan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Bo'lim nomi 3 ta harfdan kam bo'lmasligi kerak")]
        public string DepartmentNameUz { get; set; } = string.Empty;  // bo'lim nomi

        [Required(ErrorMessage = "Bo'lim bo'lishi shart")]
        [MaxLength(50, ErrorMessage = "Bo'lim nomi 50 ta harfdan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Bo'lim nomi 3 ta harfdan kam bo'lmasligi kerak")]
        public string DepartmentNameRu { get; set; } = string.Empty;  // bo'lim nomi

        [Required(ErrorMessage = "Bo'lim bo'lishi shart")]
        [MaxLength(50, ErrorMessage = "Bo'lim nomi 50 ta harfdan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Bo'lim nomi 3 ta harfdan kam bo'lmasligi kerak")]
        public string DepartmentNameEn { get; set; } = string.Empty;  // bo'lim nomi

        [MaxLength(250, ErrorMessage = "Bo'lim haqida 500 ta harfdan oshmasligi kerak")]
        [MinLength(10, ErrorMessage = "Bo'lim haqida 10 ta harfdan kam bo'lmasligi kerak")]
        public string DepartmentDescriptionUz { get; set; } = string.Empty; // bo'lim haqida

        [MaxLength(250, ErrorMessage = "Bo'lim haqida 500 ta harfdan oshmasligi kerak")]
        [MinLength(10, ErrorMessage = "Bo'lim haqida 10 ta harfdan kam bo'lmasligi kerak")]
        public string DepartmentDescriptionRu { get; set; } = string.Empty; // bo'lim haqida

        [MaxLength(250, ErrorMessage = "Bo'lim haqida 500 ta harfdan oshmasligi kerak")]
        [MinLength(10, ErrorMessage = "Bo'lim haqida 10 ta harfdan kam bo'lmasligi kerak")]
        public string DepartmentDescriptionEn { get; set; } = string.Empty; // bo'lim haqida
        public int DepartmentImageId { get; set; }  // bo'lim rasmi   
    }
}
