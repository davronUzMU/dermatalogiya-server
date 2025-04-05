using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.CustomerRep
{
    public class CustomerRepository : ICustomerRepository
    {
        private readonly AppDbContext _appDbContext;
        public CustomerRepository(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }
        public Customer AddCustomer(Customer customer)
        {
            _appDbContext.Customers.Add(customer);
            _appDbContext.SaveChanges();
            return customer;
        }

        public void DeleteCustomer(int id)
        {
            var customer = _appDbContext.Customers.Find(id);
            if (customer != null)
            {
                _appDbContext.Customers.Remove(customer);
                _appDbContext.SaveChanges();
            }
        }

        public Customer EditCustomer(Customer customer)
        {
            _appDbContext.Customers.Update(customer);
            _appDbContext.SaveChanges();
            return customer;
        }

        public List<Customer> GetCustomerAll()
        {
            return _appDbContext.Customers.ToList();
        }

        public Customer GetCustomerById(int id)
        {
            return _appDbContext.Customers.Find(id);
        }
    }
}
