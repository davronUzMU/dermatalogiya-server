using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.VideoRep
{
    public interface IVideoRepository
    {
        Task<VideoForCustomer> AddVideoAsync(VideoForCustomer video);
        Task<IEnumerable<VideoForCustomer>> GetAllVideosAsync();
        Task<VideoForCustomer?> GetVideoByIdAsync(int id);
        Task<bool> DeleteVideoAsync(int id);
    }
}
