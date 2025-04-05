using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Exceptions;
using Dermatologiya.Server.RepositoriesAll.NewsRep;

namespace Dermatologiya.Server.Services
{
    public class NewsService
    {
        private readonly INewsRepository _newsRepository;
        public NewsService(INewsRepository newsRepository)
        {
            _newsRepository = newsRepository;
        }

        internal object AddElon(NewsRequestDTO newsRequestDTO)
        {
            if (newsRequestDTO == null)
            {
                throw new NotFoundException("e'lon ma'lumotlari kiritilmagan");
            }
            if ((string.IsNullOrEmpty(newsRequestDTO.TitleUz)) && (string.IsNullOrEmpty(newsRequestDTO.TitleRu)) && (string.IsNullOrEmpty(newsRequestDTO.TitleEn)))
            {
                throw new NotFoundException("e'lon nomi kiritilmagan");
            }
            if ((string.IsNullOrEmpty(newsRequestDTO.ContentUz)) && (string.IsNullOrEmpty(newsRequestDTO.ContentRu)) && (string.IsNullOrEmpty(newsRequestDTO.ContentEn)))
            {
                throw new NotFoundException("e'lon haqida ma'lumot kiritilmagan");
            }
            var news = new Models.News
            {
                newType= "elon",
                TitleUz = newsRequestDTO.TitleUz,
                TitleRu = newsRequestDTO.TitleRu,
                TitleEn = newsRequestDTO.TitleEn,
                ContentUz = newsRequestDTO.ContentUz,
                ContentRu = newsRequestDTO.ContentRu,
                ContentEn = newsRequestDTO.ContentEn,
                ImageUrl = newsRequestDTO.ImageUrl,
                CreatedAt = DateTime.UtcNow
            };
            var news1 = _newsRepository.AddNews(news);
            return new NewsResponseDTO
            {
                Id = news1.Id,
                TitleUz = news1.TitleUz,
                TitleRu = news1.TitleRu,
                TitleEn = news1.TitleEn,
                ContentUz = news1.ContentUz,
                ContentRu = news1.ContentRu,
                ContentEn = news1.ContentEn,
                ImageUrl = news1.ImageUrl,
                CreatedAt = news1.CreatedAt
            };
        }

        public object AddNews(NewsRequestDTO newsRequestDTO)
        {
            if (newsRequestDTO == null)
            {
                throw new NotFoundException("Yangilik ma'lumotlari kiritilmagan");
            }
            if ((string.IsNullOrEmpty(newsRequestDTO.TitleUz)) && (string.IsNullOrEmpty(newsRequestDTO.TitleRu)) && (string.IsNullOrEmpty(newsRequestDTO.TitleEn)))
            {
                throw new NotFoundException("Yangilik sarlavhasi kiritilmagan");
            }
            if ((string.IsNullOrEmpty(newsRequestDTO.ContentUz)) && (string.IsNullOrEmpty(newsRequestDTO.ContentRu)) && (string.IsNullOrEmpty(newsRequestDTO.ContentEn)))
            {
                throw new NotFoundException("Yangilik matni kiritilmagan");
            }
            var news = new Models.News
            {
                newType = "news",
                TitleUz = newsRequestDTO.TitleUz,
                TitleRu = newsRequestDTO.TitleRu,
                TitleEn = newsRequestDTO.TitleEn,
                ContentUz = newsRequestDTO.ContentUz,
                ContentRu = newsRequestDTO.ContentRu,
                ContentEn = newsRequestDTO.ContentEn,
                ImageUrl = newsRequestDTO.ImageUrl,
                CreatedAt = DateTime.UtcNow
            };
            var news1 = _newsRepository.AddNews(news);
            return new NewsResponseDTO
            {
                Id = news1.Id,
                TitleUz = news1.TitleUz,
                TitleRu = news1.TitleRu,
                TitleEn = news1.TitleEn,
                ContentUz = news1.ContentUz,
                ContentRu = news1.ContentRu,
                ContentEn = news1.ContentEn,
                ImageUrl = news1.ImageUrl,
                CreatedAt = news1.CreatedAt
            };
        }

        public void DeleteElon(int id)
        {
            if(id <= 0)
            {
                throw new NotFoundException("elon id kiritilmagan");
            }
            if (_newsRepository.GetNewsById(id) == null)
            {
                throw new NotFoundException("elon topilmadi");
            }
            _newsRepository.DeleteNews(id);
        }

        internal void DeleteNews(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("Yangilik id kiritilmagan");
            }
            if (_newsRepository.GetNewsById(id) == null)
            {
                throw new NotFoundException("Yangilik topilmadi");
            }
            _newsRepository.DeleteNews(id);
        }

        public object EditElon(NewsRequestDTO newsRequestDTO, int id)
        {
            if (newsRequestDTO == null)
            {
                throw new NotFoundException("elon ma'lumotlari kiritilmagan");
            }
            if (id <= 0)
            {
                throw new NotFoundException("elon topilmadi");
            }
            if (_newsRepository.GetNewsById(id) == null)
            {
                throw new NotFoundException("elon topilmadi");
            }
            var elon=_newsRepository.GetNewsById(id);
            elon.TitleUz = newsRequestDTO.TitleUz;
            elon.TitleRu = newsRequestDTO.TitleRu;
            elon.TitleEn = newsRequestDTO.TitleEn;
            elon.ContentUz = newsRequestDTO.ContentUz;
            elon.ContentRu = newsRequestDTO.ContentRu;
            elon.ContentEn = newsRequestDTO.ContentEn;
            elon.ImageUrl = newsRequestDTO.ImageUrl;
            elon.CreatedAt = DateTime.UtcNow;

            var elon1 = _newsRepository.EditNews(elon);
            return new NewsResponseDTO
            {
                Id = elon1.Id,
                TitleUz = elon1.TitleUz,
                TitleRu = elon1.TitleRu,
                TitleEn = elon1.TitleEn,
                ContentUz = elon1.ContentUz,
                ContentRu = elon1.ContentRu,
                ContentEn = elon1.ContentEn,
                ImageUrl = elon1.ImageUrl,
                CreatedAt = elon1.CreatedAt
            };
        }

        public object EditNews(NewsRequestDTO newsRequestDTO, int id)
        {
            if (newsRequestDTO == null)
            {
                throw new NotFoundException("Yangilik ma'lumotlari kiritilmagan");
            }
            if (id <= 0)
            {
                throw new NotFoundException("Yangilik topilmadi");
            }
            if (_newsRepository.GetNewsById(id) == null)
            {
                throw new NotFoundException("Yangilik topilmadi");
            }
            var news = _newsRepository.GetNewsById(id);
            news.TitleUz = newsRequestDTO.TitleUz;
            news.TitleRu = newsRequestDTO.TitleRu;
            news.TitleEn = newsRequestDTO.TitleEn;
            news.ContentUz = newsRequestDTO.ContentUz;
            news.ContentRu = newsRequestDTO.ContentRu;
            news.ContentEn = newsRequestDTO.ContentEn;
            news.ImageUrl = newsRequestDTO.ImageUrl;
            news.CreatedAt = DateTime.UtcNow;

            var news1 = _newsRepository.EditNews(news);
            return new NewsResponseDTO
            {
                Id = news1.Id,
                TitleUz = news1.TitleUz,
                TitleRu = news1.TitleRu,
                TitleEn = news1.TitleEn,
                ContentUz = news1.ContentUz,
                ContentRu = news1.ContentRu,
                ContentEn = news1.ContentEn,
                ImageUrl = news1.ImageUrl,
                CreatedAt = news1.CreatedAt
            };
        }

        public object GetAllElon()
        {
            List<Models.News> news = _newsRepository.GetNewsAll();
            List<NewsResponseDTO> newsResponseDTOs = new List<NewsResponseDTO>();
            foreach (var item in news)
            {
                if(item.newType == "elon")
                {
                    newsResponseDTOs.Add(new NewsResponseDTO
                    {
                        Id = item.Id,
                        TitleUz = item.TitleUz,
                        TitleRu = item.TitleRu,
                        TitleEn = item.TitleEn,
                        ContentUz = item.ContentUz,
                        ContentRu = item.ContentRu,
                        ContentEn = item.ContentEn,
                        ImageUrl = item.ImageUrl,
                        CreatedAt = item.CreatedAt
                    });
                }
            }
            return newsResponseDTOs;
        }

        internal object GetAllNews()
        {
            List<Models.News> news = _newsRepository.GetNewsAll();
            List<NewsResponseDTO> newsResponseDTOs = new List<NewsResponseDTO>();
            foreach (var item in news) {
                if (item.newType == "news")
                {
                    newsResponseDTOs.Add(new NewsResponseDTO
                    {
                        Id = item.Id,
                        TitleUz = item.TitleUz,
                        TitleRu = item.TitleRu,
                        TitleEn = item.TitleEn,
                        ContentUz = item.ContentUz,
                        ContentRu = item.ContentRu,
                        ContentEn = item.ContentEn,
                        ImageUrl = item.ImageUrl,
                        CreatedAt = item.CreatedAt
                    });
                }
            }
            return newsResponseDTOs;
        }

        public object GetElonById(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("elon id kiritilmagan");
            }
            if (_newsRepository.GetNewsById(id) == null)
            {
                throw new NotFoundException("elon topilmadi");
            }

            var elon = _newsRepository.GetNewsById(id);

            return new NewsResponseDTO
            {
                Id = elon.Id,
                TitleUz = elon.TitleUz,
                TitleRu = elon.TitleRu,
                TitleEn = elon.TitleEn,
                ContentUz = elon.ContentUz,
                ContentRu = elon.ContentRu,
                ContentEn = elon.ContentEn,
                ImageUrl = elon.ImageUrl,
                CreatedAt = elon.CreatedAt
            };
        }

        public object GetNewsById(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("Yangilik id kiritilmagan");
            }
            if (_newsRepository.GetNewsById(id) == null)
            {
                throw new NotFoundException("Yangilik topilmadi");
            }
            var news = _newsRepository.GetNewsById(id);
            return new NewsResponseDTO
            {
                Id = news.Id,
                TitleUz = news.TitleUz,
                TitleRu = news.TitleRu,
                TitleEn = news.TitleEn,
                ContentUz = news.ContentUz,
                ContentRu = news.ContentRu,
                ContentEn = news.ContentEn,
                ImageUrl = news.ImageUrl,
                CreatedAt = news.CreatedAt
            };
        }
    }
}
