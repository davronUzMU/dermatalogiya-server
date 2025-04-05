using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.Models
{
    public class ImageHospital
    {
        [Key]
        public int Id { get; set; }
        public string ImageName { get; set; } = string.Empty;
        public string ImagePath { get; set; } = string.Empty;
        public DateTime CreateTime { get; set; }
    }
}
