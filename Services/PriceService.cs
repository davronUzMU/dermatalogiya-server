
using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Exceptions;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.PriseForServicesRep;

namespace Dermatologiya.Server.Services
{
    public class PriceService
    {
        private readonly IPriceForServiceRepository _priceForServiceRepository;
        public PriceService(IPriceForServiceRepository priceForServiceRepository)
        {
            _priceForServiceRepository = priceForServiceRepository;
        }

        public object AddPrice(PriceRequestDTO priceRequestDTO)
        {
            if (priceRequestDTO == null)
            {
                throw new NotFoundException("Narx haqida ma'lumotlar topilmadi !!!");
            }
            if ((string.IsNullOrEmpty(priceRequestDTO.ServiceNameUz)) && (string.IsNullOrEmpty(priceRequestDTO.ServiceNameRu)) && (string.IsNullOrEmpty(priceRequestDTO.ServiceNameEn)))
            {
                throw new NotFoundException("Xizmat nomi va narxi kiritilmagan !!!");
            }
            if(priceRequestDTO.Price <= 0)
            {
                throw new NotFoundException("Narxi kiritilmagan !!!");
            }
            var price = new PricesForServices
            {
                ServiceNameUz = priceRequestDTO.ServiceNameUz,
                ServiceNameRu = priceRequestDTO.ServiceNameRu,
                ServiceNameEn = priceRequestDTO.ServiceNameEn,
                Price = priceRequestDTO.Price
            };
            var price1 = _priceForServiceRepository.AddPricesForServices(price);
            return new PriceResponseDTO
            {
                Id = price1.Id,
                ServiceNameUz = price1.ServiceNameUz,
                ServiceNameRu = price1.ServiceNameRu,
                ServiceNameEn = price1.ServiceNameEn,
                Price = price1.Price,
                CreateTime = DateTime.UtcNow
            };
        }

        public object DeletePrice(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("Narx haqida ma'lumotlar topilmadi !!!");
            }
            if (_priceForServiceRepository.GetPricesForServicesById(id)==null)
            {
                return new { message = "Narx o'chirildi !!!" };
            }
            _priceForServiceRepository.DeletePricesForServices(id);
            return new ResponseDTO
            {
                Message = "Narx o'chirildi !!!",
                IsSuccess = true
            };
        }

        internal object EditPrice(PriceRequestDTO priceRequestDTO, int id)
        {
            if(priceRequestDTO == null)
            {
                throw new NotFoundException("Narx haqida ma'lumotlar topilmadi !!!");
            }
            if (id <= 0)
            {
                throw new NotFoundException("Narx topilmadi !!!");
            }
            if (_priceForServiceRepository.GetPricesForServicesById(id) == null)
            {
                throw new NotFoundException("Narx topilmadi !!!");
            }
            var price = _priceForServiceRepository.GetPricesForServicesById(id);
            price.ServiceNameUz = priceRequestDTO.ServiceNameUz;
            price.ServiceNameRu = priceRequestDTO.ServiceNameRu;
            price.ServiceNameEn = priceRequestDTO.ServiceNameEn;
            price.Price = priceRequestDTO.Price;
            price.CreateTime = DateTime.UtcNow;
            var price1 = _priceForServiceRepository.EditPricesForServices(price);

            return new PriceResponseDTO
            {
                Id = price1.Id,
                ServiceNameUz = price1.ServiceNameUz,
                ServiceNameRu = price1.ServiceNameRu,
                ServiceNameEn = price1.ServiceNameEn,
                Price = price1.Price,
                CreateTime = price1.CreateTime
            };
        }

        public object GetAllPrice()
        {
            List<PricesForServices> prices = _priceForServiceRepository.GetPricesForServicesAll();
            List<PriceResponseDTO> priceResponseDTOs = new List<PriceResponseDTO>();
            foreach (var item in prices)
            {
                priceResponseDTOs.Add(new PriceResponseDTO
                {
                    Id = item.Id,
                    ServiceNameUz = item.ServiceNameUz,
                    ServiceNameRu = item.ServiceNameRu,
                    ServiceNameEn = item.ServiceNameEn,
                    Price = item.Price,
                    CreateTime = item.CreateTime
                });
            }
            return priceResponseDTOs;
        }
    }
}
