
using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Exceptions;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.DoctorRep;

namespace Dermatologiya.Server.Services
{
    public class DoctorService
    {
        private readonly IDoctorRepository _doctorRepository;
        public DoctorService(IDoctorRepository doctorRepository)
        {
            _doctorRepository = doctorRepository;
        }
        internal object AddDoctors(DoctorRequestDTO doctorRequestDTO)
        {
            if (doctorRequestDTO == null)
            {
                throw new NotFoundException("Doctor haqida ma'lumotlar topilmadi !!!");
            }
            if ((string.IsNullOrEmpty(doctorRequestDTO.fullnameUz)) && (string.IsNullOrEmpty(doctorRequestDTO.fullnameRu)) && (string.IsNullOrEmpty(doctorRequestDTO.fullnameEn)))
            {
                throw new NotFoundException("Doctor F.I.O kiritilmagan !!!");
            }
            if((string.IsNullOrEmpty(doctorRequestDTO.workExperienceUz)) && (string.IsNullOrEmpty(doctorRequestDTO.workExperienceRu)) && (string.IsNullOrEmpty(doctorRequestDTO.workExperienceEn)))
            {
                throw new NotFoundException("Ish staji kiritilmagan !!!");
            }
            if((string.IsNullOrEmpty(doctorRequestDTO.DirectionUz)) && (string.IsNullOrEmpty(doctorRequestDTO.DirectionRu)) && (string.IsNullOrEmpty(doctorRequestDTO.DirectionEn)))
            {
                throw new NotFoundException("Yo'nalish kiritilmagan !!!");
            }
            if ((string.IsNullOrEmpty(doctorRequestDTO.FulBioInformationUz)) && (string.IsNullOrEmpty(doctorRequestDTO.FulBioInformationRu)) && (string.IsNullOrEmpty(doctorRequestDTO.FulBioInformationEn)))
            {
                throw new NotFoundException("To'liq bio malumot kiritilmagan !!!");
            }
            var doctor = new Doctor
            {
                fullnameUz = doctorRequestDTO.fullnameUz,
                fullnameRu = doctorRequestDTO.fullnameRu,
                fullnameEn = doctorRequestDTO.fullnameEn,
                workExperienceUz = doctorRequestDTO.workExperienceUz,
                workExperienceRu = doctorRequestDTO.workExperienceRu,
                workExperienceEn = doctorRequestDTO.workExperienceEn,
                DirectionUz = doctorRequestDTO.DirectionUz,
                DirectionRu = doctorRequestDTO.DirectionRu,
                DirectionEn = doctorRequestDTO.DirectionEn,
                FulBioInformationUz = doctorRequestDTO.FulBioInformationUz,
                FulBioInformationRu = doctorRequestDTO.FulBioInformationRu,
                FulBioInformationEn = doctorRequestDTO.FulBioInformationEn,
                DoctorImageId = doctorRequestDTO.DoctorImageId,
                CreateTime = DateTime.UtcNow
            };
            var doctor1 = _doctorRepository.AddDoctor(doctor);
            return new DoctorResponseDTO
            {
                Id = doctor1.Id,
                fullnameUz = doctor1.fullnameUz,
                fullnameRu = doctor1.fullnameRu,
                fullnameEn = doctor1.fullnameEn,
                workExperienceUz = doctor1.workExperienceUz,
                workExperienceRu = doctor1.workExperienceRu,
                workExperienceEn = doctor1.workExperienceEn,
                DirectionUz = doctor1.DirectionUz,
                DirectionRu = doctor1.DirectionRu,
                DirectionEn = doctor1.DirectionEn,
                FulBioInformationUz = doctor1.FulBioInformationUz,
                FulBioInformationRu = doctor1.FulBioInformationRu,
                FulBioInformationEn = doctor1.FulBioInformationEn,
                DoctorImageId = doctor1.DoctorImageId,
                CreateTime = doctor1.CreateTime
            };
        }

        internal object DeleteDoctors(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("Doctor topilmadi !!!");
            }
            if(_doctorRepository.GetDoctorById(id) == null)
            {
                throw new NotFoundException("Doctor topilmadi !!!");
            }
            _doctorRepository.DeleteDoctor(id);
            return new ResponseDTO
            {
                Message = "Doctor o'chirildi !!!",
                IsSuccess = true
            };
        }

        internal object EditDoctors(DoctorRequestDTO doctorRequestDTO, int id)
        {
            if (doctorRequestDTO == null)
            {
                throw new NotFoundException("Doctor haqida ma'lumotlar topilmadi !!!");
            }
            if (id <= 0)
            {
                throw new NotFoundException("Doctor topilmadi !!!");
            }
            if (_doctorRepository.GetDoctorById(id) == null)
            {
                throw new NotFoundException("Doctor topilmadi !!!");
            }
            var doctor=_doctorRepository.GetDoctorById(id);

            doctor.fullnameUz = doctorRequestDTO.fullnameUz;
            doctor.fullnameRu = doctorRequestDTO.fullnameRu;
            doctor.fullnameEn = doctorRequestDTO.fullnameEn;
            doctor.workExperienceUz = doctorRequestDTO.workExperienceUz;
            doctor.workExperienceRu = doctorRequestDTO.workExperienceRu;
            doctor.workExperienceEn = doctorRequestDTO.workExperienceEn;
            doctor.DirectionUz = doctorRequestDTO.DirectionUz;
            doctor.DirectionRu = doctorRequestDTO.DirectionRu;
            doctor.DirectionEn = doctorRequestDTO.DirectionEn;
            doctor.FulBioInformationUz = doctorRequestDTO.FulBioInformationUz;
            doctor.FulBioInformationRu = doctorRequestDTO.FulBioInformationRu;
            doctor.FulBioInformationEn = doctorRequestDTO.FulBioInformationEn;
            doctor.DoctorImageId = doctorRequestDTO.DoctorImageId;
            doctor.CreateTime = DateTime.UtcNow;

            var doctor1 = _doctorRepository.EditDoctor(doctor);
            return new DoctorResponseDTO
            {
                Id = doctor1.Id,
                fullnameUz = doctor1.fullnameUz,
                fullnameRu = doctor1.fullnameRu,
                fullnameEn = doctor1.fullnameEn,
                workExperienceUz = doctor1.workExperienceUz,
                workExperienceRu = doctor1.workExperienceRu,
                workExperienceEn = doctor1.workExperienceEn,
                DirectionUz = doctor1.DirectionUz,
                DirectionRu = doctor1.DirectionRu,
                DirectionEn = doctor1.DirectionEn,
                FulBioInformationUz = doctor1.FulBioInformationUz,
                FulBioInformationRu = doctor1.FulBioInformationRu,
                FulBioInformationEn = doctor1.FulBioInformationEn,
                DoctorImageId = doctor1.DoctorImageId,
                CreateTime = doctor1.CreateTime
            };
        }

        internal object GetDoctors()
        {
            List<Doctor> doctors = _doctorRepository.GetDoctorAll();
            List<DoctorResponseDTO> doctorResponseDTOs = new List<DoctorResponseDTO>();
            foreach (var item in doctors)
            {
                doctorResponseDTOs.Add(new DoctorResponseDTO
                {
                    Id = item.Id,
                    fullnameUz = item.fullnameUz,
                    fullnameRu = item.fullnameRu,
                    fullnameEn = item.fullnameEn,
                    workExperienceUz = item.workExperienceUz,
                    workExperienceRu = item.workExperienceRu,
                    workExperienceEn = item.workExperienceEn,
                    DirectionUz = item.DirectionUz,
                    DirectionRu = item.DirectionRu,
                    DirectionEn = item.DirectionEn,
                    FulBioInformationUz = item.FulBioInformationUz,
                    FulBioInformationRu = item.FulBioInformationRu,
                    FulBioInformationEn = item.FulBioInformationEn,
                    DoctorImageId = item.DoctorImageId,
                    CreateTime = item.CreateTime
                });
            }
            return doctorResponseDTOs;
           
        }

        public object GetDoctorsById(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("Doctor topilmadi !!!");
            }
            if (_doctorRepository.GetDoctorById(id) == null)
            {
                throw new NotFoundException("Doctor topilmadi !!!");
            }
            var doctor = _doctorRepository.GetDoctorById(id);
            return new DoctorResponseDTO
            {
                Id = doctor.Id,
                fullnameUz = doctor.fullnameUz,
                fullnameRu = doctor.fullnameRu,
                fullnameEn = doctor.fullnameEn,
                workExperienceUz = doctor.workExperienceUz,
                workExperienceRu = doctor.workExperienceRu,
                workExperienceEn = doctor.workExperienceEn,
                DirectionUz = doctor.DirectionUz,
                DirectionRu = doctor.DirectionRu,
                DirectionEn = doctor.DirectionEn,
                FulBioInformationUz = doctor.FulBioInformationUz,
                FulBioInformationRu = doctor.FulBioInformationRu,
                FulBioInformationEn = doctor.FulBioInformationEn,
                DoctorImageId = doctor.DoctorImageId,
                CreateTime = doctor.CreateTime
            };
        }
    }
}
