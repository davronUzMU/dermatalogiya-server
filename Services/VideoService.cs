using Dermatologiya.Server.AllDTOs;
using Dermatologiya.Server.Models;
using Dermatologiya.Server.RepositoriesAll.VideoRep;
using System.Diagnostics;

namespace Dermatologiya.Server.Services
{
    public class VideoService : IVideoService
    {
        private readonly IVideoRepository _videoRepository;
        private readonly IWebHostEnvironment _env;

        public VideoService(IVideoRepository videoRepository, IWebHostEnvironment env)
        {
            _videoRepository = videoRepository;
            _env = env;
        }

        public async Task<bool> DeleteVideoAsync(int id)
        {
            var video = await _videoRepository.GetVideoByIdAsync(id);
            if (video == null) return false;

            // Video fayl yo‘llarini olish
            var videoPath = Path.Combine(_env.WebRootPath, video.OriginalFileUrl.TrimStart('/'));
            var hlsFolderPath = Path.Combine(_env.WebRootPath, "VideoMP4", "hls", Path.GetFileNameWithoutExtension(videoPath));

            try
            {
                // Video faylini o‘chirish
                if (File.Exists(videoPath))
                {
                    File.Delete(videoPath);
                }

                // HLS papkasini o‘chirish (rekursiv)
                if (Directory.Exists(hlsFolderPath))
                {
                    Directory.Delete(hlsFolderPath, true);
                }

                // Ma'lumotlar bazasidan o‘chirish
                return await _videoRepository.DeleteVideoAsync(id);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Xatolik: {ex.Message}");
                return false;
            }
        }

        public async Task<IEnumerable<VideoResponseDTO>> GetAllVideosAsync()
        {
            var videos = await _videoRepository.GetAllVideosAsync();
            return videos.Select(v => new VideoResponseDTO { Id = v.Id, Description = v.Description, HlsUrl = v.HlsUrl });
        }

        public async Task<VideoResponseDTO?> GetVideoByIdAsync(int id)
        {
            var video = await _videoRepository.GetVideoByIdAsync(id);
            return video == null ? null : new VideoResponseDTO { Id = video.Id, Description = video.Description, HlsUrl = video.HlsUrl };
        }

        public async Task<VideoResponseDTO> UploadVideoAsync(VideoRequestDTO request)
        {
            var uploadsFolder = Path.Combine(_env.WebRootPath, "VideoMP4");
            Directory.CreateDirectory(uploadsFolder);

            var fileName = Guid.NewGuid() + Path.GetExtension(request.VideoFile.FileName);
            var filePath = Path.Combine(uploadsFolder, fileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await request.VideoFile.CopyToAsync(stream);
            }

            // HLS format uchun papkalarni yaratish
            var hlsFolder = Path.Combine(uploadsFolder, "hls", Path.GetFileNameWithoutExtension(fileName));
            Directory.CreateDirectory(hlsFolder);

            string[] resolutions = { "240p", "480p", "720p" };
            Dictionary<string, string> resolutionMap = new Dictionary<string, string>
    {
        { "240p", "426x240" },
        { "480p", "854x480" },
        { "720p", "1280x720" }
    };

            List<Task> ffmpegTasks = new List<Task>();

            foreach (var res in resolutions)
            {
                var resolutionFolder = Path.Combine(hlsFolder, res);
                Directory.CreateDirectory(resolutionFolder);

                string size = resolutionMap[res];
                var segmentPath = Path.Combine(resolutionFolder, "index_%03d.ts");
                var playlistPath = Path.Combine(resolutionFolder, "index.m3u8");

                string ffmpegCmd = $"-i \"{filePath}\" -s {size} -b:v {500 * (Array.IndexOf(resolutions, res) + 1)}k " +
                                   $"-maxrate {550 * (Array.IndexOf(resolutions, res) + 1)}k -bufsize {1000 * (Array.IndexOf(resolutions, res) + 1)}k " +
                                   $"-hls_time 6 -hls_playlist_type vod -hls_segment_filename \"{segmentPath}\" -f hls \"{playlistPath}\"";

                ffmpegTasks.Add(RunFFmpegAsync(ffmpegCmd));
            }

            await Task.WhenAll(ffmpegTasks); // ✅ **Parallel transkoding tugaguncha kutish**

            // **Master playlist yaratish**
            var masterPlaylist = Path.Combine(hlsFolder, "index.m3u8");
            var masterPlaylistContent = "#EXTM3U\n";
            foreach (var res in resolutions)
            {
                masterPlaylistContent += $"#EXT-X-STREAM-INF:BANDWIDTH={500 * (Array.IndexOf(resolutions, res) + 1) * 1000},RESOLUTION={resolutionMap[res]}\n";
                masterPlaylistContent += $"{res}/index.m3u8\n";
            }

            await File.WriteAllTextAsync(masterPlaylist, masterPlaylistContent);

            var video = new VideoForCustomer
            {
                Description = request.Description,
                OriginalFileUrl = $"/VideoMP4/{fileName}",
                HlsUrl = $"/VideoMP4/hls/{Path.GetFileNameWithoutExtension(fileName)}/index.m3u8",
                UploadedAt = DateTime.UtcNow
            };

            video = await _videoRepository.AddVideoAsync(video);
            return new VideoResponseDTO { Id = video.Id, Description = video.Description, HlsUrl = video.HlsUrl };
        }

        // ✅ **FFmpeg jarayonini asinxron ishlash uchun yordamchi metod**
        private async Task RunFFmpegAsync(string arguments)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = @"C:\Users\User\ffmpeg\ffmpeg-7.1-essentials_build\bin\ffmpeg.exe",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.OutputDataReceived += (sender, args) => Console.WriteLine(args.Data);
            process.ErrorDataReceived += (sender, args) => Console.WriteLine(args.Data);

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync(); // ✅ **Jarayonni asinxron kutish**
        }



    }
}

//using Amazon.S3;
//using Amazon.S3.Model;
//using Amazon.S3.Transfer;
//using Dermatologiya.Server.AllDTOs;
//using Dermatologiya.Server.Models;
//using Dermatologiya.Server.RepositoriesAll.VideoRep;
//using Dermatologiya.Server.Services;
//using Microsoft.Extensions.Options;
//using Minio;
//using Minio.DataModel.Args;
//using System.Diagnostics;

//public class VideoService : IVideoService
//{
//    private readonly IVideoRepository _videoRepository;
//    private readonly MinioSettings _minioSettings;
//    private readonly MinioClient _minioClient;

//    public VideoService(IVideoRepository videoRepository, IOptions<MinioSettings> minioSettings)
//    {
//        _videoRepository = videoRepository;
//        _minioSettings = minioSettings.Value;
//        _minioClient = (MinioClient?)new MinioClient()
//            .WithEndpoint(_minioSettings.Endpoint)
//            .WithCredentials(_minioSettings.AccessKey, _minioSettings.SecretKey)
//            .WithSSL(false)
//            .Build();
//    }

//    public async Task<VideoResponseDTO> UploadVideoAsync(VideoRequestDTO request)
//    {
//        var fileName = $"{Guid.NewGuid()}{Path.GetExtension(request.VideoFile.FileName)}";

//        using (var stream = request.VideoFile.OpenReadStream())
//        {
//            var putObjectArgs = new PutObjectArgs()
//                .WithBucket(_minioSettings.BucketName)
//                .WithObject(fileName)
//                .WithStreamData(stream)
//                .WithObjectSize(request.VideoFile.Length)
//                .WithContentType(request.VideoFile.ContentType);

//            await _minioClient.PutObjectAsync(putObjectArgs);
//        }

//        var videoUrl = $"{_minioSettings.Endpoint}/{_minioSettings.BucketName}/{fileName}";

//        var video = new VideoForCustomer
//        {
//            Description = request.Description,
//            OriginalFileUrl = videoUrl,
//            HlsUrl = videoUrl,
//            UploadedAt = DateTime.UtcNow
//        };

//        video = await _videoRepository.AddVideoAsync(video);
//        return new VideoResponseDTO { Id = video.Id, Description = video.Description, HlsUrl = video.HlsUrl };
//    }

//    public async Task<IEnumerable<VideoResponseDTO>> GetAllVideosAsync()
//    {
//        var videos = await _videoRepository.GetAllVideosAsync();
//        return videos.Select(v => new VideoResponseDTO { Id = v.Id, Description = v.Description, HlsUrl = v.HlsUrl });
//    }

//    public async Task<VideoResponseDTO?> GetVideoByIdAsync(int id)
//    {
//        var video = await _videoRepository.GetVideoByIdAsync(id);
//        return video == null ? null : new VideoResponseDTO { Id = video.Id, Description = video.Description, HlsUrl = video.HlsUrl };
//    }

//    public async Task<bool> DeleteVideoAsync(int id)
//    {
//        var video = await _videoRepository.GetVideoByIdAsync(id);
//        if (video == null) return false;

//        try
//        {
//            var removeArgs = new RemoveObjectArgs()
//                .WithBucket(_minioSettings.BucketName)
//                .WithObject(Path.GetFileName(video.OriginalFileUrl));
//            await _minioClient.RemoveObjectAsync(removeArgs);
//            return await _videoRepository.DeleteVideoAsync(id);
//        }
//        catch (Exception ex)
//        {
//            Console.WriteLine($"Xatolik: {ex.Message}");
//            return false;
//        }
//    }
//}


