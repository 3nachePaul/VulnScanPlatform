using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;

namespace VulnScanPlatform.Hubs
{
    public class ScanHub : Hub
    {
        // Această metodă permite clientului să se alăture unui grup specific unui raport
        public async Task JoinReportGroup(string reportId)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, $"Report-{reportId}");
        }
    }
}