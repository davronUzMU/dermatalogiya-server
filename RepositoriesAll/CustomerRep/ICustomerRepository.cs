using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.CustomerRep
{
    public interface ICustomerRepository
    {
        List<Customer> GetCustomerAll();
        Customer GetCustomerById(int id);
        Customer AddCustomer(Customer customer);
        Customer EditCustomer(Customer customer);
        void DeleteCustomer(int id);
    }
}
