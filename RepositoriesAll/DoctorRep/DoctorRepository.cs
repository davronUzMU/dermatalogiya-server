using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.DoctorRep
{
    public class DoctorRepository : IDoctorRepository
    {
        private readonly AppDbContext _appDbContext;
        public DoctorRepository(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }
        public Doctor AddDoctor(Doctor doctor)
        {
            _appDbContext.Doctors.Add(doctor);
            _appDbContext.SaveChanges();
            return doctor;
        }

        public void DeleteDoctor(int id)
        {
            var doctor = _appDbContext.Doctors.Find(id);
            if (doctor != null)
            {
                _appDbContext.Doctors.Remove(doctor);
                _appDbContext.SaveChanges();
            }
        }

        public Doctor EditDoctor(Doctor doctor)
        {
            _appDbContext.Doctors.Update(doctor);
            _appDbContext.SaveChanges();
            return doctor;
        }

        public List<Doctor> GetDoctorAll()
        {
            return _appDbContext.Doctors.ToList();
        }

        public Doctor GetDoctorById(int id)
        {
            return _appDbContext.Doctors.Find(id);
        }
    }
}
