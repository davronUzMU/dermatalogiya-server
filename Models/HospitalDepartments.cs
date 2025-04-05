using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.Models
{
    public class HospitalDepartments
    {
        [Key]
        public int Id { get; set; }
        public string DepartmentNameUz { get; set; } = string.Empty;  // bo'lim nomi
        public string DepartmentNameRu { get; set; } = string.Empty;  // bo'lim nomi
        public string DepartmentNameEn { get; set; } = string.Empty;  // bo'lim nomi
        public string DepartmentDescriptionUz { get; set; } = string.Empty; // bo'lim haqida
        public string DepartmentDescriptionRu { get; set; } = string.Empty; // bo'lim haqida
        public string DepartmentDescriptionEn { get; set; } = string.Empty; // bo'lim haqida

        public int DepartmentImageId { get; set; }  // bo'lim rasmi
        public DateTime CreateTime { get; set; }
    }
}
