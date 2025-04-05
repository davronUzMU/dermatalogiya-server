using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.BlockRep
{
    public class BlockRootRepository : IBlockRootRepository
    {
        private readonly AppDbContext _appDbContext;
        public BlockRootRepository(AppDbContext context)
        {
            _appDbContext = context;
        }
        public BlockRoot AddBlockRoot(BlockRoot blockRoot)
        {
            _appDbContext.HospitalBlockRoots.Add(blockRoot);
            _appDbContext.SaveChanges();
            return blockRoot;
        }

        public void DeleteBlockRoot(int id)
        {
            var blockRoot = _appDbContext.HospitalBlockRoots.Find(id);
            if (blockRoot != null)
            {
                _appDbContext.HospitalBlockRoots.Remove(blockRoot);
                _appDbContext.SaveChanges();
            }
        }

        public BlockRoot EditBlockRoot(BlockRoot blockRoot)
        {
            _appDbContext.HospitalBlockRoots.Update(blockRoot);
            _appDbContext.SaveChanges();
            return blockRoot;
        }

        public List<BlockRoot> GetBlockRootAll()
        {
            return _appDbContext.HospitalBlockRoots.ToList();
        }

        public BlockRoot GetBlockRootById(int id)
        {
            return _appDbContext.HospitalBlockRoots.Find(id);
        }
    }
}
