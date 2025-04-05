using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;

namespace Dermatologiya.Server.RepositoriesAll.HospitalBlockRep
{
    public class BlockRepository : IBlockRepository
    {
        private readonly AppDbContext _appDbContext;
        public BlockRepository(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }
        public HospitalBlock AddBlock(HospitalBlock hospitalBlock)
        {
            _appDbContext.Blocks.Add(hospitalBlock);
            _appDbContext.SaveChanges();
            return hospitalBlock;
        }

        public void DeleteBlock(int id)
        {
            var block = _appDbContext.Blocks.Find(id);
            if (block != null)
            {
                _appDbContext.Blocks.Remove(block);
                _appDbContext.SaveChanges();
            }
        }

        public HospitalBlock EditBlock(HospitalBlock hospitalBlock)
        {
            _appDbContext.Blocks.Update(hospitalBlock);
            _appDbContext.SaveChanges();
            return hospitalBlock;
        }

        public List<HospitalBlock> GetBlockAll()
        {
            return _appDbContext.Blocks.ToList();
        }

        public HospitalBlock GetBlockById(int id)
        {
            return _appDbContext.Blocks.Find(id);
        }
    }
}
