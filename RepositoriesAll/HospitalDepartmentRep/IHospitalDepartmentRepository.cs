using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.HospitalDepartmentRep
{
    public interface IHospitalDepartmentRepository
    {
        List<HospitalDepartments> GetHospitalDepartmentsAll();
        HospitalDepartments GetHospitalDepartmentsById(int id);
        HospitalDepartments AddHospitalDepartments(HospitalDepartments hospitalDepartments);
        HospitalDepartments EditHospitalDepartments(HospitalDepartments hospitalDepartments);
        void DeleteHospitalDepartments(int id);
    }
}
