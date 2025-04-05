using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.DoctorRep
{
    public interface IDoctorRepository
    {
        List<Doctor> GetDoctorAll();
        Doctor GetDoctorById(int id);
        Doctor AddDoctor(Doctor doctor);
        Doctor EditDoctor(Doctor doctor);
        void DeleteDoctor(int id);
    }
}
