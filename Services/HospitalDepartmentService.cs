
using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Exceptions;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.HospitalDepartmentRep;

namespace Dermatologiya.Server.Services
{
    public class HospitalDepartmentService
    {
        private readonly IHospitalDepartmentRepository _hospitalDepartmentRepository;
        public HospitalDepartmentService(IHospitalDepartmentRepository hospitalDepartmentRepository)
        {
            _hospitalDepartmentRepository = hospitalDepartmentRepository;
        }
        public object AddHospitalDepartments(HospitalDepartmentRequestDTO hospitalDepartmentRequestDTO)
        {
            if (hospitalDepartmentRequestDTO == null)
            {
                throw new NotFoundException("Bo'lim haqida ma'lumotlar topilmadi !!!");
            }
            if ((string.IsNullOrEmpty(hospitalDepartmentRequestDTO.DepartmentNameUz)) && (string.IsNullOrEmpty(hospitalDepartmentRequestDTO.DepartmentNameRu)) && (string.IsNullOrEmpty(hospitalDepartmentRequestDTO.DepartmentNameEn)))
            {
                throw new NotFoundException("Bo'lim nomi kiritilmagan !!!");
            }
            if ((string.IsNullOrEmpty(hospitalDepartmentRequestDTO.DepartmentDescriptionUz)) && (string.IsNullOrEmpty(hospitalDepartmentRequestDTO.DepartmentDescriptionRu)) && (string.IsNullOrEmpty(hospitalDepartmentRequestDTO.DepartmentDescriptionEn)))
            {
                throw new NotFoundException("Bo'lim haqida ma'lumot kiritilmagan !!!");
            }
            var hospitalDepartment = new HospitalDepartments
            {
                DepartmentNameUz = hospitalDepartmentRequestDTO.DepartmentNameUz,
                DepartmentNameRu = hospitalDepartmentRequestDTO.DepartmentNameRu,
                DepartmentNameEn = hospitalDepartmentRequestDTO.DepartmentNameEn,
                DepartmentDescriptionUz = hospitalDepartmentRequestDTO.DepartmentDescriptionUz,
                DepartmentDescriptionRu = hospitalDepartmentRequestDTO.DepartmentDescriptionRu,
                DepartmentDescriptionEn = hospitalDepartmentRequestDTO.DepartmentDescriptionEn,
                DepartmentImageId = hospitalDepartmentRequestDTO.DepartmentImageId,
                CreateTime = DateTime.UtcNow
            };
            var hospitalDepartment1 = _hospitalDepartmentRepository.AddHospitalDepartments(hospitalDepartment);
            return new HospitalDepartmentResponseDTO
            {
                Id = hospitalDepartment1.Id,
                DepartmentNameUz = hospitalDepartment1.DepartmentNameUz,
                DepartmentNameRu = hospitalDepartment1.DepartmentNameRu,
                DepartmentNameEn = hospitalDepartment1.DepartmentNameEn,
                DepartmentDescriptionUz = hospitalDepartment1.DepartmentDescriptionUz,
                DepartmentDescriptionRu = hospitalDepartment1.DepartmentDescriptionRu,
                DepartmentDescriptionEn = hospitalDepartment1.DepartmentDescriptionEn,
                DepartmentImageId = hospitalDepartment1.DepartmentImageId,
                CreateTime = hospitalDepartment1.CreateTime
            };
        }

        public object DeleteHospitalDepartments(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("Bo'lim haqida ma'lumotlar topilmadi !!!");
            }
            if(_hospitalDepartmentRepository.GetHospitalDepartmentsById(id) == null)
            {
                throw new NotFoundException("Bo'lim topilmadi !!!");
            }
            _hospitalDepartmentRepository.DeleteHospitalDepartments(id);
            return new ResponseDTO { 
                Message = "Bo'lim o'chirildi !!!",
                IsSuccess = true
            };
        }

        public object EditHospitalDepartments(HospitalDepartmentRequestDTO hospitalDepartmentRequestDTO, int id)
        {
            if (hospitalDepartmentRequestDTO == null)
            {
                throw new NotFoundException("Bo'lim haqida ma'lumotlar topilmadi !!!");
            }
            if (id <= 0)
            {
                throw new NotFoundException("Bo'lim topilmadi !!!");
            }
            if (_hospitalDepartmentRepository.GetHospitalDepartmentsById(id) == null)
            {
                throw new NotFoundException("Bo'lim topilmadi !!!");
            }
            var hospitalDepartment = _hospitalDepartmentRepository.GetHospitalDepartmentsById(id);
            if (hospitalDepartment == null)
            {
                throw new NotFoundException("Bo'lim topilmadi !!!");
            }
            hospitalDepartment.DepartmentNameUz = hospitalDepartmentRequestDTO.DepartmentNameUz;
            hospitalDepartment.DepartmentNameRu = hospitalDepartmentRequestDTO.DepartmentNameRu;
            hospitalDepartment.DepartmentNameEn = hospitalDepartmentRequestDTO.DepartmentNameEn;
            hospitalDepartment.DepartmentDescriptionUz = hospitalDepartmentRequestDTO.DepartmentDescriptionUz;
            hospitalDepartment.DepartmentDescriptionRu = hospitalDepartmentRequestDTO.DepartmentDescriptionRu;
            hospitalDepartment.DepartmentDescriptionEn = hospitalDepartmentRequestDTO.DepartmentDescriptionEn;
            hospitalDepartment.DepartmentImageId = hospitalDepartmentRequestDTO.DepartmentImageId;
            hospitalDepartment.CreateTime = DateTime.UtcNow;
            var hospitalDepartment1 = _hospitalDepartmentRepository.EditHospitalDepartments(hospitalDepartment);

            return new HospitalDepartmentResponseDTO
            {
                Id = hospitalDepartment1.Id,
                DepartmentNameUz = hospitalDepartment1.DepartmentNameUz,
                DepartmentNameRu = hospitalDepartment1.DepartmentNameRu,
                DepartmentNameEn = hospitalDepartment1.DepartmentNameEn,
                DepartmentDescriptionUz = hospitalDepartment1.DepartmentDescriptionUz,
                DepartmentDescriptionRu = hospitalDepartment1.DepartmentDescriptionRu,
                DepartmentDescriptionEn = hospitalDepartment1.DepartmentDescriptionEn,
                DepartmentImageId = hospitalDepartment1.DepartmentImageId,
                CreateTime = hospitalDepartment1.CreateTime
            };
        }

        public object GetHospitalDepartments()
        {
            List<HospitalDepartments> hospitalDepartments = _hospitalDepartmentRepository.GetHospitalDepartmentsAll();
            List<HospitalDepartmentResponseDTO> hospitalDepartmentResponseDTOs = new List<HospitalDepartmentResponseDTO>();
            foreach (var item in hospitalDepartments)
            {
                hospitalDepartmentResponseDTOs.Add(new HospitalDepartmentResponseDTO
                {
                    Id = item.Id,
                    DepartmentNameUz = item.DepartmentNameUz,
                    DepartmentNameRu = item.DepartmentNameRu,
                    DepartmentNameEn = item.DepartmentNameEn,
                    DepartmentDescriptionUz = item.DepartmentDescriptionUz,
                    DepartmentDescriptionRu = item.DepartmentDescriptionRu,
                    DepartmentDescriptionEn = item.DepartmentDescriptionEn,
                    DepartmentImageId = item.DepartmentImageId,
                    CreateTime = item.CreateTime
                });
            }

            return hospitalDepartmentResponseDTOs;
        }
    }
}
