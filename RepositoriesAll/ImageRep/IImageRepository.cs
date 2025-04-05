using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.ImageRep
{
    public interface IImageRepository
    {
        Task<ImageHospital> AddImageHospitalAsync(ImageHospital image);
        Task<IEnumerable<ImageHospital>> GetAllImageHospitalAsync();
        Task<ImageHospital?> GetImageHospitalByIdAsync(int id);
        Task<bool> DeleteImageHospitalAsync(int id);
    }
}
