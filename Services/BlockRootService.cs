
using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Exceptions;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.BlockRep;

namespace Dermatologiya.Server.Services
{
    public class BlockRootService
    {
        private readonly IBlockRootRepository _blockRootRepository;
        public BlockRootService(IBlockRootRepository blockRootRepository)
        {
            _blockRootRepository = blockRootRepository;
        }
        public object AddHospitalBlocksRoot(BlockRootRequestDTO blockRootRequestDTO)
        {
            if(blockRootRequestDTO == null)
            {
                throw new NotFoundException("Block haqida ma'lumotlar topilmadi !!!");
            }
            if((string.IsNullOrEmpty(blockRootRequestDTO.ContentUz)) && (string.IsNullOrEmpty(blockRootRequestDTO.ContentRu)) && (string.IsNullOrEmpty(blockRootRequestDTO.ContentEn)))
            {
                throw new NotFoundException("Block nomi kiritilmagan !!!");
            }
            if(blockRootRequestDTO.HospitalBlockId <= 0)
            {
                throw new NotFoundException("umumiy block kiritilmagan !!!");
            }
            var blockRoot = new BlockRoot
            {
                ContentUz = blockRootRequestDTO.ContentUz,
                ContentRu = blockRootRequestDTO.ContentRu,
                ContentEn = blockRootRequestDTO.ContentEn,
                ImageUrl = blockRootRequestDTO.ImageUrl,
                HospitalBlockId = blockRootRequestDTO.HospitalBlockId,
                CreatedAt = DateTime.UtcNow

            };
           var blockRoot1 = _blockRootRepository.AddBlockRoot(blockRoot);
            return new BlockRootResponseDTO
            {
                Id = blockRoot1.Id,
                ContentUz = blockRoot1.ContentUz,
                ContentRu = blockRoot1.ContentRu,
                ContentEn = blockRoot1.ContentEn,
                ImageUrl = blockRoot1.ImageUrl,
                HospitalBlockId = blockRoot1.HospitalBlockId,
                CreatedAt = blockRoot1.CreatedAt
            };
        }

        public object DeleteHospitalBlocksRoot(int id)
        {
            if (id <= 0)
            {
                throw new NotFoundException("Block topilmadi !!!");
            }
            if(_blockRootRepository.GetBlockRootById(id) == null)
            {
                throw new NotFoundException("Block topilmadi !!!");
            }
            _blockRootRepository.DeleteBlockRoot(id);
            return new ResponseDTO
            {
                Message = "Block o'chirildi !!!",
                IsSuccess = true

            };
        }

        public object EditHospitalBlocksRoot(BlockRootRequestDTO blockRootRequestDTO, int id)
        {
            if (blockRootRequestDTO == null)
            {
                throw new NotFoundException("Block haqida ma'lumotlar topilmadi !!!");
            }
            if (id <= 0)
            {
                throw new NotFoundException("Block topilmadi !!!");
            }
            if (_blockRootRepository.GetBlockRootById(id) == null)
            {
                throw new NotFoundException("Block topilmadi !!!");
            }
            if (blockRootRequestDTO.HospitalBlockId <= 0)
            {
                throw new NotFoundException("umumiy block kiritilmagan !!!");
            }
            var block2=_blockRootRepository.GetBlockRootById(id);
            block2.ContentUz = blockRootRequestDTO.ContentUz;
            block2.ContentRu = blockRootRequestDTO.ContentRu;
            block2.ContentEn = blockRootRequestDTO.ContentEn;
            block2.ImageUrl = blockRootRequestDTO.ImageUrl;
            block2.HospitalBlockId = blockRootRequestDTO.HospitalBlockId;
            block2.CreatedAt = DateTime.UtcNow;

            _blockRootRepository.EditBlockRoot(block2);
            return new BlockRootResponseDTO
            {
                Id = block2.Id,
                ContentUz = block2.ContentUz,
                ContentRu = block2.ContentRu,
                ContentEn = block2.ContentEn,
                ImageUrl = block2.ImageUrl,
                HospitalBlockId = block2.HospitalBlockId,
                CreatedAt = block2.CreatedAt
            };
        }

        public object GetHospitalBlocksRoot()
        {
            List<BlockRoot> blockRoots = _blockRootRepository.GetBlockRootAll();
            List<BlockRootResponseDTO> blockRootResponseDTOs = new List<BlockRootResponseDTO>();
            foreach (var blockRoot in blockRoots)
            {
                blockRootResponseDTOs.Add(new BlockRootResponseDTO
                {
                    Id = blockRoot.Id,
                    ContentUz = blockRoot.ContentUz,
                    ContentRu = blockRoot.ContentRu,
                    ContentEn = blockRoot.ContentEn,
                    ImageUrl = blockRoot.ImageUrl,
                    HospitalBlockId = blockRoot.HospitalBlockId,
                    CreatedAt = blockRoot.CreatedAt
                });
            }
            return blockRootResponseDTOs;
        }
    }
}
