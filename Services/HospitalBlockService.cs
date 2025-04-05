
using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Exceptions;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.HospitalBlockRep;

namespace Dermatologiya.Server.Services
{
    public class HospitalBlockService
    {
        private readonly IBlockRepository _hospitalBlockRepository;
        public HospitalBlockService(IBlockRepository hospitalBlockRepository)
        {
            _hospitalBlockRepository = hospitalBlockRepository;
        }
        public object AddHospitalBlocks(HospitalBlockRequestDTO hospitalBlockRequestDTO)
        {
            if (hospitalBlockRequestDTO == null)
            {
                throw new NotFoundException("HospitalBlock haqida ma'lumotlar topilmadi !!!");
            }
            if ((string.IsNullOrEmpty(hospitalBlockRequestDTO.BlockNameUz)) && (string.IsNullOrEmpty(hospitalBlockRequestDTO.BlockNameRu)) && (string.IsNullOrEmpty(hospitalBlockRequestDTO.BlockNameEn)))
            {
                throw new NotFoundException("Block nomi kiritilmagan !!!");
            }
            if ((string.IsNullOrEmpty(hospitalBlockRequestDTO.HighTextUz)) && (string.IsNullOrEmpty(hospitalBlockRequestDTO.HighTextRu)) && (string.IsNullOrEmpty(hospitalBlockRequestDTO.HighTextEn))
                && (string.IsNullOrEmpty(hospitalBlockRequestDTO.MiddleTextUz)) && (string.IsNullOrEmpty(hospitalBlockRequestDTO.MiddleTextRu)) && (string.IsNullOrEmpty(hospitalBlockRequestDTO.MiddleTextEn))
                && (string.IsNullOrEmpty(hospitalBlockRequestDTO.LowTextUz)) && (string.IsNullOrEmpty(hospitalBlockRequestDTO.LowTextRu)) && (string.IsNullOrEmpty(hospitalBlockRequestDTO.LowTextEn)))
            {
                throw new NotFoundException("Matn kiritilmagan !!!");
            }
            var hospitalBlock = new HospitalBlock
            {
                BlockNameUz = hospitalBlockRequestDTO.BlockNameUz,
                BlockNameRu = hospitalBlockRequestDTO.BlockNameRu,
                BlockNameEn = hospitalBlockRequestDTO.BlockNameEn,
                ImageId = hospitalBlockRequestDTO.ImageId,
                VideoId = hospitalBlockRequestDTO.VideoId,
                HighTextUz = hospitalBlockRequestDTO.HighTextUz,
                HighTextRu = hospitalBlockRequestDTO.HighTextRu,
                HighTextEn = hospitalBlockRequestDTO.HighTextEn,
                MiddleTextUz = hospitalBlockRequestDTO.MiddleTextUz,
                MiddleTextRu = hospitalBlockRequestDTO.MiddleTextRu,
                MiddleTextEn = hospitalBlockRequestDTO.MiddleTextEn,
                LowTextUz = hospitalBlockRequestDTO.LowTextUz,
                LowTextRu = hospitalBlockRequestDTO.LowTextRu,
                LowTextEn = hospitalBlockRequestDTO.LowTextEn,
                CreateTime = DateTime.UtcNow
            };
            var hospitalBlock1 = _hospitalBlockRepository.AddBlock(hospitalBlock);
            return new HospitalBlockResponseDTO
            {
                Id = hospitalBlock1.Id,
                BlockNameUz = hospitalBlock1.BlockNameUz,
                BlockNameRu = hospitalBlock1.BlockNameRu,
                BlockNameEn = hospitalBlock1.BlockNameEn,
                ImageId = hospitalBlock1.ImageId,
                VideoId = hospitalBlock1.VideoId,
                HighTextUz = hospitalBlock1.HighTextUz,
                HighTextRu = hospitalBlock1.HighTextRu,
                HighTextEn = hospitalBlock1.HighTextEn,
                MiddleTextUz = hospitalBlock1.MiddleTextUz,
                MiddleTextRu = hospitalBlock1.MiddleTextRu,
                MiddleTextEn = hospitalBlock1.MiddleTextEn,
                LowTextUz = hospitalBlock1.LowTextUz,
                LowTextRu = hospitalBlock1.LowTextRu,
                LowTextEn = hospitalBlock1.LowTextEn,
                CreateTime = hospitalBlock1.CreateTime
            };
            
        }

        public object DeleteHospitalBlocks(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("HospitalBlock id kiritilmagan !!!");
            }
            if (_hospitalBlockRepository.GetBlockById(id) == null)
            {
                throw new NotFoundException("HospitalBlock topilmadi !!!");
            }
            _hospitalBlockRepository.DeleteBlock(id);
            return new ResponseDTO
            {
                Message = "HospitalBlock o'chirildi !!!",
                IsSuccess = true

            };
        }

        public object EditHospitalBlocks(HospitalBlockRequestDTO hospitalBlockRequestDTO, int id)
        {
            if (hospitalBlockRequestDTO == null)
            {
                throw new NotFoundException("HospitalBlock haqida ma'lumotlar topilmadi !!!");
            }
            if (id <= 0)
            {
                throw new NotFoundException("HospitalBlock id kiritilmagan !!!");
            }
            if (_hospitalBlockRepository.GetBlockById(id) == null)
            {
                throw new NotFoundException("HospitalBlock topilmadi !!!");
            }

            var hospitalBlock=_hospitalBlockRepository.GetBlockById(id);
            hospitalBlock.BlockNameUz = hospitalBlockRequestDTO.BlockNameUz;
            hospitalBlock.BlockNameRu = hospitalBlockRequestDTO.BlockNameRu;
            hospitalBlock.BlockNameEn = hospitalBlockRequestDTO.BlockNameEn;
            hospitalBlock.ImageId = hospitalBlockRequestDTO.ImageId;
            hospitalBlock.VideoId = hospitalBlockRequestDTO.VideoId;
            hospitalBlock.HighTextUz = hospitalBlockRequestDTO.HighTextUz;
            hospitalBlock.HighTextRu = hospitalBlockRequestDTO.HighTextRu;
            hospitalBlock.HighTextEn = hospitalBlockRequestDTO.HighTextEn;
            hospitalBlock.MiddleTextUz = hospitalBlockRequestDTO.MiddleTextUz;
            hospitalBlock.MiddleTextRu = hospitalBlockRequestDTO.MiddleTextRu;
            hospitalBlock.MiddleTextEn = hospitalBlockRequestDTO.MiddleTextEn;
            hospitalBlock.LowTextUz = hospitalBlockRequestDTO.LowTextUz;
            hospitalBlock.LowTextRu = hospitalBlockRequestDTO.LowTextRu;
            hospitalBlock.LowTextEn = hospitalBlockRequestDTO.LowTextEn;
            hospitalBlock.CreateTime = DateTime.UtcNow;
            var hospitalBlock1 = _hospitalBlockRepository.EditBlock(hospitalBlock);
            return new HospitalBlockResponseDTO
            {
                Id = hospitalBlock1.Id,
                BlockNameUz = hospitalBlock1.BlockNameUz,
                BlockNameRu = hospitalBlock1.BlockNameRu,
                BlockNameEn = hospitalBlock1.BlockNameEn,
                ImageId = hospitalBlock1.ImageId,
                VideoId = hospitalBlock1.VideoId,
                HighTextUz = hospitalBlock1.HighTextUz,
                HighTextRu = hospitalBlock1.HighTextRu,
                HighTextEn = hospitalBlock1.HighTextEn,
                MiddleTextUz = hospitalBlock1.MiddleTextUz,
                MiddleTextRu = hospitalBlock1.MiddleTextRu,
                MiddleTextEn = hospitalBlock1.MiddleTextEn,
                LowTextUz = hospitalBlock1.LowTextUz,
                LowTextRu = hospitalBlock1.LowTextRu,
                LowTextEn = hospitalBlock1.LowTextEn,
                CreateTime = hospitalBlock1.CreateTime
            };
        }

        public object GetHospitalBlocks()
        {
            List<HospitalBlock> hospitalBlocks = _hospitalBlockRepository.GetBlockAll();
            List<HospitalBlockResponseDTO> hospitalBlockResponseDTOs = new List<HospitalBlockResponseDTO>();
            foreach (var hospitalBlock in hospitalBlocks)
            {
                hospitalBlockResponseDTOs.Add(new HospitalBlockResponseDTO
                {
                    Id = hospitalBlock.Id,
                    BlockNameUz = hospitalBlock.BlockNameUz,
                    BlockNameRu = hospitalBlock.BlockNameRu,
                    BlockNameEn = hospitalBlock.BlockNameEn,
                    ImageId = hospitalBlock.ImageId,
                    VideoId = hospitalBlock.VideoId,
                    HighTextUz = hospitalBlock.HighTextUz,
                    HighTextRu = hospitalBlock.HighTextRu,
                    HighTextEn = hospitalBlock.HighTextEn,
                    MiddleTextUz = hospitalBlock.MiddleTextUz,
                    MiddleTextRu = hospitalBlock.MiddleTextRu,
                    MiddleTextEn = hospitalBlock.MiddleTextEn,
                    LowTextUz = hospitalBlock.LowTextUz,
                    LowTextRu = hospitalBlock.LowTextRu,
                    LowTextEn = hospitalBlock.LowTextEn,
                    CreateTime = hospitalBlock.CreateTime
                });
            }
            return hospitalBlockResponseDTOs;
        }

        public object GetHospitalBlocksById(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("HospitalBlock id kiritilmagan !!!");
            }
            if (_hospitalBlockRepository.GetBlockById(id) == null)
            {
                throw new NotFoundException("HospitalBlock topilmadi !!!");
            }
            var hospitalBlock = _hospitalBlockRepository.GetBlockById(id);
            return new HospitalBlockResponseDTO
            {
                Id = hospitalBlock.Id,
                BlockNameUz = hospitalBlock.BlockNameUz,
                BlockNameRu = hospitalBlock.BlockNameRu,
                BlockNameEn = hospitalBlock.BlockNameEn,
                ImageId = hospitalBlock.ImageId,
                VideoId = hospitalBlock.VideoId,
                HighTextUz = hospitalBlock.HighTextUz,
                HighTextRu = hospitalBlock.HighTextRu,
                HighTextEn = hospitalBlock.HighTextEn,
                MiddleTextUz = hospitalBlock.MiddleTextUz,
                MiddleTextRu = hospitalBlock.MiddleTextRu,
                MiddleTextEn = hospitalBlock.MiddleTextEn,
                LowTextUz = hospitalBlock.LowTextUz,
                LowTextRu = hospitalBlock.LowTextRu,
                LowTextEn = hospitalBlock.LowTextEn,
                CreateTime = hospitalBlock.CreateTime
            };
        }
    }
}
