using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.PriseForServicesRep
{
    public interface IPriceForServiceRepository
    {
        List<PricesForServices> GetPricesForServicesAll();
        PricesForServices GetPricesForServicesById(int id);
        PricesForServices AddPricesForServices(PricesForServices pricesForServices);
        PricesForServices EditPricesForServices(PricesForServices pricesForServices);
        void DeletePricesForServices(int id);
    }
}
