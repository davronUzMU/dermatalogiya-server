namespace Dermatologiya.Server.AllDTOs
{
    public class PriceResponseDTO
    {
        public int Id { get; set; }
        public string ServiceNameUz { get; set; } = string.Empty;
        public string ServiceNameRu { get; set; } = string.Empty;
        public string ServiceNameEn { get; set; } = string.Empty;

        public double Price { get; set; }
        public DateTime CreateTime { get; set; }
    }
}
