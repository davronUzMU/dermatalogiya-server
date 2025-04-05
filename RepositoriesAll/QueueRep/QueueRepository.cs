using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.QueueRep
{
    public class QueueRepository : IQueueRepository
    {
        private readonly AppDbContext _appDbContext;
        public QueueRepository(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }
        public Queue AddQueue(Queue queue)
        {
            _appDbContext.Queues.Add(queue);
            _appDbContext.SaveChanges();
            return queue;
        }

        public void DeleteQueue(int id)
        {
            var customer = _appDbContext.Queues.Find(id);
            if (customer != null)
            {
                _appDbContext.Queues.Remove(customer);
                _appDbContext.SaveChanges();
            }
        }

        public Queue EditQueue(Queue queue)
        {
            _appDbContext.Queues.Update(queue);
            _appDbContext.SaveChanges();
            return queue;
        }

        public List<Queue> GetQueueAll()
        {
            return _appDbContext.Queues.ToList();
        }

        public Queue GetQueueById(int id)
        {
            return _appDbContext.Queues.Find(id);
        }

    }
}
