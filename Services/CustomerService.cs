
using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Exceptions;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.CustomerRep;

namespace Dermatologiya.Server.Services
{
    public class CustomerService
    {
        private readonly ICustomerRepository _customerRepository;
        public CustomerService(ICustomerRepository customerRepository)
        {
            _customerRepository = customerRepository;
        }
        public object AddCustomers(CustomerRequestDTO customerRequestDTO)
        {
            if (customerRequestDTO == null)
            {
                throw new NotFoundException("Mijoz haqida ma'lumotlar topilmadi !!!");
            }
            if((string.IsNullOrEmpty(customerRequestDTO.FullName)) && (string.IsNullOrEmpty(customerRequestDTO.PhoneNumber)))
            {
                throw new NotFoundException("Mijoz haqida ma'lumotlar to'liq kiritilmagan !!!");
            }
            var customer = new Customer
            {
                FullName = customerRequestDTO.FullName,
                PhoneNumber = customerRequestDTO.PhoneNumber,
                Description = customerRequestDTO.Description,
                CreateTime = DateTime.UtcNow
            };
           var customer2 = _customerRepository.AddCustomer(customer);

            return new CustomerResponseDTO
            {
                Id = customer2.Id,
                FullName = customer2.FullName,
                PhoneNumber = customer2.PhoneNumber,
                Description = customer2.Description,
                CreateTime = customer2.CreateTime
            };
        }

        internal object DeleteCustomers(int id)
        {
            if(id <= 0)
            {
                throw new NotFoundException("Mijoz topilmadi !!!");
            }
            if(_customerRepository.GetCustomerById(id) == null)
            {
                throw new NotFoundException("Mijoz topilmadi !!!");
            }
            _customerRepository.DeleteCustomer(id);

            return new ResponseDTO
            {
                Message = "Mijoz o'chirildi !!!",
                IsSuccess = true
            };
        }

        internal object EditCustomers(CustomerRequestDTO customerRequestDTO, int id)
        {
            if (customerRequestDTO == null)
            {
                throw new NotFoundException("Mijoz haqida ma'lumotlar topilmadi !!!");
            }
          
            if (id <= 0)
            {
                throw new NotFoundException("Mijoz topilmadi !!!");
            }
            if (_customerRepository.GetCustomerById(id) == null)
            {
                throw new NotFoundException("Mijoz topilmadi !!!");
            }
            var customer=_customerRepository.GetCustomerById(id);
            customer.FullName = customerRequestDTO.FullName;
            customer.PhoneNumber = customerRequestDTO.PhoneNumber;
            customer.Description = customerRequestDTO.Description;
            customer.CreateTime = DateTime.UtcNow;

            var customer2 = _customerRepository.EditCustomer(customer);

            return new CustomerResponseDTO
            {
                Id = customer2.Id,
                FullName = customer2.FullName,
                PhoneNumber = customer2.PhoneNumber,
                Description = customer2.Description,
                CreateTime = customer2.CreateTime
            };

        }

        internal object GetCustomers()
        {
            List<Customer> customers = _customerRepository.GetCustomerAll();
            List<CustomerResponseDTO> customerResponseDTOs = new List<CustomerResponseDTO>();
            foreach (var item in customers)
            {
                customerResponseDTOs.Add(new CustomerResponseDTO
                {
                    Id = item.Id,
                    FullName = item.FullName,
                    PhoneNumber = item.PhoneNumber,
                    Description = item.Description,
                    CreateTime = item.CreateTime
                });
            }
            return customerResponseDTOs;
        }
    }
}
