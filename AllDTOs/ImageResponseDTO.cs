namespace Dermatologiya.Server.AllDTOs
{
    public class ImageResponseDTO
    {
        public int Id { get; set; }
        public string ImageName { get; set; } = string.Empty;
        public string ImagePath { get; set; } = string.Empty;
        public DateTime CreateTime { get; set; }
    }
}
