using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace Dermatologiya.Server.RepositoriesAll.ImageRep
{
    public class ImageRepository : IImageRepository
    {
        private readonly AppDbContext _context;
        public ImageRepository(AppDbContext context) => _context = context;

        public async Task<ImageHospital> AddImageHospitalAsync(ImageHospital image)
        {
            await _context.ImageHospitals.AddAsync(image);
            await _context.SaveChangesAsync();
            return image;
        }

        public async Task<bool> DeleteImageHospitalAsync(int id)
        {
            var img = await _context.ImageHospitals.FindAsync(id);
            if (img == null) return false;
            _context.ImageHospitals.Remove(img);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<IEnumerable<ImageHospital>> GetAllImageHospitalAsync()
        {
            return await _context.ImageHospitals.ToListAsync();
        }

        public async Task<ImageHospital?> GetImageHospitalByIdAsync(int id)
        {
            return await _context.ImageHospitals.FindAsync(id);
        }
    }
}
