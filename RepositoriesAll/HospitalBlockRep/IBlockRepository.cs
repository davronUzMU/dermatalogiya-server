using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.HospitalBlockRep
{
    public interface IBlockRepository
    {
        List<HospitalBlock> GetBlockAll();
        HospitalBlock GetBlockById(int id);
        HospitalBlock AddBlock(HospitalBlock hospitalBlock);
        HospitalBlock EditBlock(HospitalBlock hospitalBlock);
        void DeleteBlock(int id);
    }
}
