namespace VulnScanPlatform.Services
{
    public interface IScanService
    {
        Task ProcessScanAsync(int scanId);
    }
}