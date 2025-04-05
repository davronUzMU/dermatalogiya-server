using System.ComponentModel.DataAnnotations;

namespace Dermatologiya.Server.Models
{
    public class Queue
    {
        [Key]
        public int Id { get; set; }
        public int QueueId { get; set; }
        public int CustomerId { get; set; }
        public int DoctorId { get; set; }
        public DateTime CreateTime { get; set; }
    }
}
