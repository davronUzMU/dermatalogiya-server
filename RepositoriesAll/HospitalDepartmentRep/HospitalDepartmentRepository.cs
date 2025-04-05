using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.HospitalDepartmentRep
{
    public class HospitalDepartmentRepository : IHospitalDepartmentRepository
    {
        private readonly AppDbContext _appDbContext;
        public HospitalDepartmentRepository(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }
        public HospitalDepartments AddHospitalDepartments(HospitalDepartments hospitalDepartments)
        {
            _appDbContext.HospitalDepartments.Add(hospitalDepartments);
            _appDbContext.SaveChanges();
            return hospitalDepartments;
        }

        public void DeleteHospitalDepartments(int id)
        {
            var customer = _appDbContext.HospitalDepartments.Find(id);
            if (customer != null)
            {
                _appDbContext.HospitalDepartments.Remove(customer);
                _appDbContext.SaveChanges();
            }
        }

        public HospitalDepartments EditHospitalDepartments(HospitalDepartments hospitalDepartments)
        {
            _appDbContext.HospitalDepartments.Update(hospitalDepartments);
            _appDbContext.SaveChanges();
            return hospitalDepartments;
        }

        public List<HospitalDepartments> GetHospitalDepartmentsAll()
        {
            return _appDbContext.HospitalDepartments.ToList();
        }

        public HospitalDepartments GetHospitalDepartmentsById(int id)
        {
            return _appDbContext.HospitalDepartments.Find(id);
        }
    }
}
