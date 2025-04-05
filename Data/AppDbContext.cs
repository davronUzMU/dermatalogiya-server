using Dermatologiya.Server.Controllers;
using Dermatologiya.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Dermatologiya.Server.Data
{
    public class AppDbContext:IdentityDbContext<IdentityUser>
    {
        protected readonly IConfiguration _configuration;
        public AppDbContext(DbContextOptions<AppDbContext> options, IConfiguration configuration)
          : base(options)
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseNpgsql(_configuration.GetConnectionString("WebApiDatabase"));
            //base.OnConfiguring(optionsBuilder);
        }
        public DbSet<Customer> Customers { get; set; }
        public DbSet<Queue> Queues { get; set; }
        public DbSet<PricesForServices> PricesForServices { get; set; }
        public DbSet<ImageHospital> ImageHospitals { get; set; }
        public DbSet<Doctor> Doctors { get; set; }
        public DbSet<VideoForCustomer> videoForCustomers { get; set; }
        public DbSet<News> GetNews { get; set; }
        public DbSet<BlockRoot> HospitalBlockRoots { get; set; }
        public DbSet<HospitalDepartments> HospitalDepartments { get; set; }
        public DbSet<HospitalBlock> Blocks { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {

            base.OnModelCreating(modelBuilder);

        }
    }
}
