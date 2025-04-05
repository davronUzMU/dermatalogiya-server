using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.Models
{
    public class Doctor
    {
        [Key]
        public int Id { get; set; }
        public string fullnameUz { get; set; }=string.Empty;
        public string fullnameRu { get; set; } = string.Empty;
        public string fullnameEn { get; set; } = string.Empty;

        public string workExperienceUz { get; set; } = string.Empty;
        public string workExperienceRu { get; set; } = string.Empty;
        public string workExperienceEn { get; set; } = string.Empty;

        public string DirectionUz { get; set; } = string.Empty;  //yo'nalish
        public string DirectionRu { get; set; } = string.Empty;  //направление
        public string DirectionEn { get; set; } = string.Empty;  //direction
        public string FulBioInformationUz { get; set; } = string.Empty;  //to'liq bio malumot
        public string FulBioInformationRu { get; set; } = string.Empty;  //полная био информация
        public string FulBioInformationEn { get; set; } = string.Empty;  //full bio information
        public int DoctorImageId { get; set; }
        public DateTime CreateTime { get; set; }
    }
}
