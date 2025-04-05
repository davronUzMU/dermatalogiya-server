using Dermatologiya.Server.AllDTOs;

namespace Dermatologiya.Server.Services
{
    public interface IVideoService
    {
        Task<VideoResponseDTO> UploadVideoAsync(VideoRequestDTO request);
        Task<IEnumerable<VideoResponseDTO>> GetAllVideosAsync();
        Task<VideoResponseDTO?> GetVideoByIdAsync(int id);
        Task<bool> DeleteVideoAsync(int id);
    }
}
