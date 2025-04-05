namespace Dermatologiya.Server.AllDTOs
{
    public class HospitalBlockResponseDTO
    {
        public int Id { get; set; }
        public string BlockNameUz { get; set; } = string.Empty;
        public string BlockNameRu { get; set; } = string.Empty;
        public string BlockNameEn { get; set; } = string.Empty;

        public int ImageId { get; set; }
        public int VideoId { get; set; }


        public string HighTextUz { get; set; } = string.Empty;
        public string HighTextRu { get; set; } = string.Empty;
        public string HighTextEn { get; set; } = string.Empty;

        public string MiddleTextUz { get; set; } = string.Empty;
        public string MiddleTextRu { get; set; } = string.Empty;
        public string MiddleTextEn { get; set; } = string.Empty;

        public string LowTextUz { get; set; } = string.Empty;
        public string LowTextRu { get; set; } = string.Empty;
        public string LowTextEn { get; set; } = string.Empty;

        public DateTime CreateTime { get; set; }
    }
}
