using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.Models
{
    public class BlockRoot
    {
        [Key]
        public int Id { get; set; }
        public string ContentUz { get; set; } = string.Empty; 
        public string ContentRu { get; set; } = string.Empty; 
        public string ContentEn { get; set; } = string.Empty;
        public int ImageUrl { get; set; }
        public int HospitalBlockId { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
