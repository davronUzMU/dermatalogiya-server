
using Dermatologiya.Server.Data;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.BlockRep;
using Dermatologiya.Server.RepositoriesAll.CustomerRep;
using Dermatologiya.Server.RepositoriesAll.DoctorRep;
using Dermatologiya.Server.RepositoriesAll.HospitalBlockRep;
using Dermatologiya.Server.RepositoriesAll.HospitalDepartmentRep;
using Dermatologiya.Server.RepositoriesAll.ImageRep;
using Dermatologiya.Server.RepositoriesAll.NewsRep;
using Dermatologiya.Server.RepositoriesAll.PriseForServicesRep;
using Dermatologiya.Server.RepositoriesAll.QueueRep;
using Dermatologiya.Server.RepositoriesAll.VideoRep;
using Dermatologiya.Server.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.Tokens;
using Minio;
using System.Runtime;
using System.Text;
using DotNetEnv; // DotNetEnv paketini import qilish

namespace Dermatologiya.Server
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // .env faylini yuklash
            Env.Load(); // DotNetEnv yordamida .env faylini o‘qish

            var builder = WebApplication.CreateBuilder(args);

          
            string? connectionString = Env.GetString("CONNECTIONSTRINGS__WEBAPIDATABASE");
            builder.Services.AddDbContext<AppDbContext>(options =>
                options.UseNpgsql(connectionString));
            Console.WriteLine(Env.GetString("CONNECTIONSTRINGS__WEBAPIDATABASE"));


            // CORS sozlamalari
            const string CorsPolicy = "CorsPolicy";
            builder.Services.AddCors(options =>
            {
                options.AddPolicy(CorsPolicy, policy =>
                {
                    policy.AllowAnyOrigin()
                          .AllowAnyMethod()
                          .AllowAnyHeader();
                });
            });


            var secretKey = Env.GetString("JWTSETTINGS__SECRETKEY");
            var issuer = Env.GetString("JWTSETTINGS__ISSUER");
            var audience = Env.GetString("JWTSETTINGS__AUDIENCE");
            var tokenLifetime = Env.GetInt("JWTSETTINGS__TOKENLIFETIME");


            var key = Encoding.UTF8.GetBytes(secretKey);

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = true,
                        ValidIssuer = issuer,
                        ValidateAudience = true,
                        ValidAudience = audience,
                        ValidateLifetime = true
                    };
                });

            builder.Services.Configure<FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = 200_000_000; // 200MB
            });

            // Repository va Service larni DI ga qo‘shish
            builder.Services.AddScoped<IVideoRepository, VideoRepository>();
            builder.Services.AddScoped<IImageRepository, ImageRepository>();
            builder.Services.AddScoped<IBlockRootRepository, BlockRootRepository>();
            builder.Services.AddScoped<ICustomerRepository, CustomerRepository>();
            builder.Services.AddScoped<IDoctorRepository, DoctorRepository>();
            builder.Services.AddScoped<IBlockRepository, BlockRepository>();
            builder.Services.AddScoped<IHospitalDepartmentRepository, HospitalDepartmentRepository>();
            builder.Services.AddScoped<INewsRepository, NewsRepository>();
            builder.Services.AddScoped<IPriceForServiceRepository, PriceForServiceRepository>();
            builder.Services.AddScoped<IQueueRepository, QueueRepository>();

            builder.Services.AddScoped<IVideoService, VideoService>();
            builder.Services.AddScoped<IImageService, ImageService>();
            builder.Services.AddScoped<BlockRootService>();
            builder.Services.AddScoped<CustomerService>();
            builder.Services.AddScoped<DoctorService>();
            builder.Services.AddScoped<HospitalBlockService>();
            builder.Services.AddScoped<HospitalDepartmentService>();
            builder.Services.AddScoped<NewsService>();
            builder.Services.AddScoped<PriceService>();
            builder.Services.AddScoped<QueueService>();
            builder.Services.AddScoped<JwtService>();

            // MVC controllers
            builder.Services.AddControllersWithViews();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Static fayllarni xizmat qilish
            app.UseWhen(context => context.Request.Path.StartsWithSegments("/VideoMP4/hls"), appBuilder =>
            {
                appBuilder.UseCors("CorsPolicy");

                var provider = new FileExtensionContentTypeProvider();
                provider.Mappings[".m3u8"] = "application/x-mpegURL";
                provider.Mappings[".ts"] = "video/MP2T";

                appBuilder.UseStaticFiles(new StaticFileOptions
                {
                    ContentTypeProvider = provider,
                    FileProvider = new PhysicalFileProvider(Path.Combine(builder.Environment.WebRootPath, "VideoMP4/hls")),
                    RequestPath = "/VideoMP4/hls"
                });
            });

            // Swagger faqat development muhitida ishlaydi
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseRouting();

            app.UseCors(CorsPolicy);

            app.UseHttpsRedirection();
            app.UseAuthorization();
            app.MapControllers();

            app.MapFallbackToFile("/index.html");

            app.Run();
        }
    }
}

