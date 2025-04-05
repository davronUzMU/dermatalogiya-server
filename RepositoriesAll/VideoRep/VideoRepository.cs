using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace Dermatologiya.Server.RepositoriesAll.VideoRep
{
    public class VideoRepository:IVideoRepository
    {
        private readonly AppDbContext _context;
        public VideoRepository(AppDbContext context) => _context = context;

        public async Task<VideoForCustomer> AddVideoAsync(VideoForCustomer video)
        {
            await _context.videoForCustomers.AddAsync(video);
            await _context.SaveChangesAsync();
            return video;
        }

        public async Task<IEnumerable<VideoForCustomer>> GetAllVideosAsync()
            => await _context.videoForCustomers.ToListAsync();

        public async Task<VideoForCustomer?> GetVideoByIdAsync(int id)
            => await _context.videoForCustomers.FindAsync(id);

        public async Task<bool> DeleteVideoAsync(int id)
        {
            var video = await _context.videoForCustomers.FindAsync(id);
            if (video == null) return false;
            _context.videoForCustomers.Remove(video);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}
