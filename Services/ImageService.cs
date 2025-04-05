using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.ImageRep;

namespace Dermatologiya.Server.Services
{
    public class ImageService : IImageService
    {
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IImageRepository _imageRepository;
        public ImageService(IWebHostEnvironment webHostEnvironment, IImageRepository imageRepository)
        {
            _webHostEnvironment = webHostEnvironment;
            _imageRepository = imageRepository;
        }


        public async Task<ImageResponseDTO> UploadImage(IFormFile file)
        {
            try
            {
                if (file.Length > 0)
                {

                    string path = _webHostEnvironment.WebRootPath + "\\Img\\";
                    if (!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }

                    string uniqueFileName = Guid.NewGuid().ToString() + "_" + file.FileName;
                    string fullPath = Path.Combine(path, uniqueFileName);

                    var image = new ImageHospital
                    {
                        ImageName = file.FileName,
                        ImagePath = fullPath,
                        CreateTime = DateTime.UtcNow
                    };

                    var img2 = await _imageRepository.AddImageHospitalAsync(image);
                    using (FileStream fileStream = System.IO.File.Create(path + file.FileName))
                    {
                        file.CopyTo(fileStream);
                        fileStream.Flush();

                        return new ImageResponseDTO { Id = img2.Id, ImageName = img2.ImageName, ImagePath = img2.ImagePath, CreateTime = img2.CreateTime };

                    }

                }
                else
                {
                    return new ImageResponseDTO();
                }

            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public async Task<IEnumerable<ImageResponseDTO>> GetAll()
        {
            var imageHospitals = await _imageRepository.GetAllImageHospitalAsync();
            var imageResponseDTOs = imageHospitals.Select(item => new ImageResponseDTO
            {
                Id = item.Id,
                ImageName = item.ImageName,
                ImagePath = item.ImagePath,
                CreateTime = item.CreateTime
            });

            return imageResponseDTOs;
        }

        public async Task<string?> GetImageById(int Id)
        {
            var image = await _imageRepository.GetImageHospitalByIdAsync(Id);

            if (image == null)
            {
                return "Rasmlar mavjud emas!!!";
            }

            string fileName = image.ImageName;
            string path = Path.Combine(_webHostEnvironment.WebRootPath, "Img", fileName);

            return File.Exists(path) ? path : null;
        }

        public async Task<bool> DeleteById(int Id)
        {
            var image = await _imageRepository.GetImageHospitalByIdAsync(Id);
            if (image == null)
            {
                return false;
            }

            string fileName = image.ImageName;
            var result = await _imageRepository.DeleteImageHospitalAsync(Id);

            if (!result)
            {
                return false;
            }

            string path = Path.Combine(_webHostEnvironment.WebRootPath, "Img", fileName);
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            return true;
        }
    }
}
