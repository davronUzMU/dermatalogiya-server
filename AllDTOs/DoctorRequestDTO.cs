using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.AllDTOs
{
    public class DoctorRequestDTO
    {
        [Required(ErrorMessage ="Ism kiritish majburiy")]
        [MaxLength(50, ErrorMessage = "Ismingiz 50 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Ismingiz 3 ta belgidan kam bo'lmasin")]
        public string fullnameUz { get; set; } = string.Empty;

        [Required(ErrorMessage = "Ism kiritish majburiy")]
        [MaxLength(50, ErrorMessage = "Ismingiz 50 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Ismingiz 3 ta belgidan kam bo'lmasin")]
        public string fullnameRu { get; set; } = string.Empty;

        [Required(ErrorMessage = "Ism kiritish majburiy")]
        [MaxLength(50, ErrorMessage = "Ismingiz 50 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Ismingiz 3 ta belgidan kam bo'lmasin")]
        public string fullnameEn { get; set; } = string.Empty;

        [Required(ErrorMessage = "Ish staji kiritish majburiy")]
        [MaxLength(25, ErrorMessage = "Ish stajingiz 25 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Ish stajingiz 3 ta belgidan kam bo'lmasin")]
        public string workExperienceUz { get; set; } = string.Empty;



        [Required(ErrorMessage = "Ish staji kiritish majburiy")]
        [MaxLength(25, ErrorMessage = "Ish stajingiz 25 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Ish stajingiz 3 ta belgidan kam bo'lmasin")]
        public string workExperienceRu { get; set; } = string.Empty;


        [Required(ErrorMessage = "Ish staji kiritish majburiy")]
        [MaxLength(25, ErrorMessage = "Ish stajingiz 25 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Ish stajingiz 3 ta belgidan kam bo'lmasin")]
        public string workExperienceEn { get; set; } = string.Empty;

        [Required(ErrorMessage = "Yo'nalish kiritish majburiy")]
        [MaxLength(75, ErrorMessage = "Yo'nalish 75 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Yo'nalish 3 ta belgida kam bo'lmasin")]
        public string DirectionUz { get; set; } = string.Empty;  //yo'nalish

        [Required(ErrorMessage = "Yo'nalish kiritish majburiy")]
        [MaxLength(75, ErrorMessage = "Yo'nalish 75 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Yo'nalish 3 ta belgida kam bo'lmasin")]
        public string DirectionRu { get; set; } = string.Empty;  //направление

        [Required(ErrorMessage = "Yo'nalish kiritish majburiy")]
        [MaxLength(75, ErrorMessage = "Yo'nalish 75 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "Yo'nalish 3 ta belgida kam bo'lmasin")]
        public string DirectionEn { get; set; } = string.Empty;  //direction


        [MaxLength(250, ErrorMessage = "To'liq bio malumot 250 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "To'liq bio malumot 3 ta belgida kam bo'lmasin")]
        public string FulBioInformationUz { get; set; } = string.Empty;  //to'liq bio malumot

        [MaxLength(250, ErrorMessage = "To'liq bio malumot 250 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "To'liq bio malumot 3 ta belgida kam bo'lmasin")]
        public string FulBioInformationRu { get; set; } = string.Empty;  //полная био информация

        [MaxLength(250, ErrorMessage = "To'liq bio malumot 250 ta belgidan oshmasligi kerak")]
        [MinLength(3, ErrorMessage = "To'liq bio malumot 3 ta belgida kam bo'lmasin")]
        public string FulBioInformationEn { get; set; } = string.Empty;  //full bio information
        public int DoctorImageId { get; set; }
    }
}
