using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.NewsRep
{
    public class NewsRepository : INewsRepository
    {
        private readonly AppDbContext _appDbContext;
        public NewsRepository(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }
        public News AddNews(News news)
        {
            _appDbContext.GetNews.Add(news);
            _appDbContext.SaveChanges();
            return news;
        }

        public void DeleteNews(int id)
        {
            var customer = _appDbContext.GetNews.Find(id);
            if (customer != null)
            {
                _appDbContext.GetNews.Remove(customer);
                _appDbContext.SaveChanges();
            }
        }

        public News EditNews(News news)
        {
            _appDbContext.GetNews.Update(news);
            _appDbContext.SaveChanges();
            return news;
        }

        public List<News> GetNewsAll()
        {
            return _appDbContext.GetNews.ToList();
        }

        public News GetNewsById(int id)
        {
            return _appDbContext.GetNews.Find(id);
        }
    }
}
