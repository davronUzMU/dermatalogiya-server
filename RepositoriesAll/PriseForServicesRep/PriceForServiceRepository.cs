using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.PriseForServicesRep
{
    public class PriceForServiceRepository : IPriceForServiceRepository
    {
        private readonly AppDbContext _appDbContext;
        public PriceForServiceRepository(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }
        public PricesForServices AddPricesForServices(PricesForServices pricesForServices)
        {
            _appDbContext.PricesForServices.Add(pricesForServices);
            _appDbContext.SaveChanges();
            return pricesForServices;
        }

        public void DeletePricesForServices(int id)
        {
            var customer = _appDbContext.PricesForServices.Find(id);
            if (customer != null)
            {
                _appDbContext.PricesForServices.Remove(customer);
                _appDbContext.SaveChanges();
            }
        }

        public PricesForServices EditPricesForServices(PricesForServices pricesForServices)
        {
            _appDbContext.PricesForServices.Update(pricesForServices);
            _appDbContext.SaveChanges();
            return pricesForServices;
        }

        public List<PricesForServices> GetPricesForServicesAll()
        {
            return _appDbContext.PricesForServices.ToList();
        }

        public PricesForServices GetPricesForServicesById(int id)
        {
            return _appDbContext.PricesForServices.Find(id);
        }
    }
}
