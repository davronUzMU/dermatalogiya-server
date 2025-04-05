namespace Dermatologiya.Server.AllDTOs
{
    public class QueueResponseDTO
    {
        public int Id { get; set; }
        public int QueueId { get; set; }
        public int CustomerId { get; set; }
        public int DoctorId { get; set; }
        public DateTime CreateTime { get; set; }
    }
}
 