// Services/IScanService.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using System.Text.RegularExpressions;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Services
{
    public interface IScanService
    {
        Task ProcessScanAsync(int scanId);
    }
}

