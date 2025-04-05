using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.QueueRep
{
    public interface IQueueRepository
    {
        List<Queue> GetQueueAll();
        Queue GetQueueById(int id);
        Queue AddQueue(Queue queue);
        Queue EditQueue(Queue queue);
        void DeleteQueue(int id);
    }
}
