using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.BlockRep
{
    public interface IBlockRootRepository
    {
        List<BlockRoot> GetBlockRootAll();
        BlockRoot GetBlockRootById(int id);
        BlockRoot AddBlockRoot(BlockRoot blockRoot);
        BlockRoot EditBlockRoot(BlockRoot blockRoot);
        void DeleteBlockRoot(int id);
    }
}
