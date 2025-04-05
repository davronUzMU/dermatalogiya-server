using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.NewsRep
{
    public interface INewsRepository
    {
        List<News> GetNewsAll();
        News GetNewsById(int id);
        News AddNews(News news);
        News EditNews(News news);
        void DeleteNews(int id);
    }
}
