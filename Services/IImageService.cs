using Dermatologiya.Server.AllDTOs;

namespace Dermatologiya.Server.Services
{
    public interface IImageService
    {
        Task<ImageResponseDTO> UploadImage(IFormFile file);
        Task<bool> DeleteById(int Id);
        Task<IEnumerable<ImageResponseDTO>> GetAll();
        Task<string?> GetImageById(int Id);
    }
}
