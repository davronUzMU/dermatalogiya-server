using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.Models
{
    public class PricesForServices
    {
        [Key]
        public int Id { get; set; }
        public string ServiceNameUz { get; set; } = string.Empty;
        public string ServiceNameRu { get; set; } = string.Empty;
        public string ServiceNameEn { get; set; } = string.Empty;

        public double Price { get; set; }
        public DateTime CreateTime { get; set; }
    }
}
