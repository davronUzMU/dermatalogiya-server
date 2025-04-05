namespace Dermatologiya.Server.AllDTOs
{
    public class BlockRootRequestDTO
    {
        public string ContentUz { get; set; } = string.Empty;
        public string ContentRu { get; set; } = string.Empty;
        public string ContentEn { get; set; } = string.Empty;
        public int ImageUrl { get; set; }
        public int HospitalBlockId { get; set; }
    }
}
