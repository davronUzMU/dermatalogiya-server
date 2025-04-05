namespace Dermatologiya.Server.AllDTOs
{
    public class CustomerResponseDTO
    {
        public int Id { get; set; }
        public string FullName { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime CreateTime { get; set; }
    }
}
