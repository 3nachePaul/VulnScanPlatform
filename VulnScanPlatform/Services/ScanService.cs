using HtmlAgilityPack;
using Microsoft.EntityFrameworkCore;
using VulnScanPlatform.Models;
using VulnScanPlatform.Hubs;
using Microsoft.AspNetCore.SignalR;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System;
using System.IO;

namespace VulnScanPlatform.Services
{
    public class ScanService : IScanService
    {
        private readonly ApplicationDbContext _context;
        private readonly IHubContext<ScanHub> _hubContext;
        private readonly ILogger<ScanService> _logger;

        public ScanService(ApplicationDbContext context, IHubContext<ScanHub> hubContext, ILogger<ScanService> logger)
        {
            _context = context;
            _hubContext = hubContext;
            _logger = logger;
        }

        public async Task StartScan(int applicationId, string scanType, string htmlContent)
        {
            var application = await _context.Applications.FindAsync(applicationId);
            if (application == null)
            {
                _logger.LogError("Application with ID {ApplicationId} not found.", applicationId);
                return;
            }

            var scan = new Scan
            {
                ApplicationId = applicationId,
                Type = Enum.Parse<ScanType>(scanType, true),
                Status = ScanStatus.InProgress,
                StartedAt = DateTime.UtcNow
            };

            _context.Scans.Add(scan);
            await _context.SaveChangesAsync();

            await _hubContext.Clients.All.SendAsync("ReceiveScanUpdate", scan.Id, scan.Status, 0);

            try
            {
                // Parsează vulnerabilitățile și le adaugă la context
                await ParseAndSaveVulnerabilities(htmlContent, scan);

                scan.Status = ScanStatus.Completed;

                // Crează și salvează raportul HTML
                var reportContent = await CreateReport(scan);
                var relativeReportPath = await SaveReportToFile(reportContent);

                // Crează entitatea Report în baza de date
                var report = new Report
                {
                    Title = $"Raport de Scanare - {application.Name} - {DateTime.Now:dd-MM-yyyy}",
                    Content = reportContent,
                    CreatedAt = DateTime.UtcNow,
                    ScanId = scan.Id,
                    CreatedByUserId = application.UserId
                };
                _context.Reports.Add(report);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scan failed for ApplicationId {ApplicationId}", applicationId);
                scan.Status = ScanStatus.Failed;
            }
            finally
            {
                scan.EndedAt = DateTime.UtcNow;
                _context.Scans.Update(scan);
                await _context.SaveChangesAsync();
                await _hubContext.Clients.All.SendAsync("ReceiveScanUpdate", scan.Id, scan.Status, 100);
            }
        }

        public async Task ProcessScanAsync(int scanId)
        {
            // Placeholder implementation for the missing interface method
            _logger.LogInformation("Processing scan with ID {ScanId}", scanId);
            var scan = await _context.Scans.FindAsync(scanId);
            if (scan == null)
            {
                _logger.LogError("Scan with ID {ScanId} not found.", scanId);
                return;
            }

            // Add logic to process the scan as needed
            scan.Status = ScanStatus.Pending;
            _context.Scans.Update(scan);
            await _context.SaveChangesAsync();
        }

        private async Task ParseAndSaveVulnerabilities(string htmlContent, Scan scan)
        {
            var document = new HtmlDocument();
            document.LoadHtml(htmlContent);

            // 1. Verifică formulare nesecurizate (metoda GET)
            var forms = document.DocumentNode.SelectNodes("//form");
            if (forms != null)
            {
                foreach (var form in forms)
                {
                    if (form.GetAttributeValue("method", "get").Equals("get", StringComparison.OrdinalIgnoreCase))
                    {
                        var action = form.GetAttributeValue("action", "N/A");
                        scan.Vulnerabilities.Add(new Vulnerability
                        {
                            Title = "Formular nesecurizat (metoda GET)",
                            Description = $"Formularul cu acțiunea '{action}' folosește metoda GET. Datele sensibile pot fi expuse în URL, istoricul browser-ului și log-urile server-ului.",
                            Severity = Severity.Low,
                            Recommendation = "Folosiți metoda POST pentru toate formularele care manipulează date, în special cele sensibile.",
                            Type = VulnerabilityType.SecurityMisconfiguration,
                            DetectedAt = DateTime.UtcNow
                        });
                    }
                }
            }

            // 2. Verifică câmpuri de parolă nesecurizate
            var passwordFields = document.DocumentNode.SelectNodes("//input[@type='password']");
            if (passwordFields != null)
            {
                foreach (var field in passwordFields)
                {
                    if (field.GetAttributeValue("autocomplete", "") != "new-password")
                    {
                        var fieldName = field.GetAttributeValue("name", "N/A");
                        scan.Vulnerabilities.Add(new Vulnerability
                        {
                            Title = "Câmp de parolă nesecurizat",
                            Description = $"Câmpul de parolă cu numele '{fieldName}' nu are atributul 'autocomplete=\"new-password\"', ceea ce poate duce la salvarea parolelor în mod nesigur de către managerii de parole din browser.",
                            Severity = Severity.Medium,
                            Recommendation = "Adăugați atributul 'autocomplete=\"new-password\"' la toate câmpurile de parolă pentru a spori securitatea.",
                            Type = VulnerabilityType.InsecureConfiguration,
                            DetectedAt = DateTime.UtcNow
                        });
                    }
                }
            }

            // 3. Verifică link-uri externe nesecurizate (risc de tabnabbing)
            var links = document.DocumentNode.SelectNodes("//a[@target='_blank']");
            if (links != null)
            {
                foreach (var link in links)
                {
                    var rel = link.GetAttributeValue("rel", "");
                    if (!rel.Contains("noopener") || !rel.Contains("noreferrer"))
                    {
                        var href = link.GetAttributeValue("href", "#");
                        scan.Vulnerabilities.Add(new Vulnerability
                        {
                            Title = "Link extern nesecurizat (risc de tabnabbing)",
                            Description = $"Link-ul către '{href}' se deschide într-un tab nou fără 'rel=\"noopener noreferrer\"', permițând paginii noi să aibă acces la obiectul `window` al paginii originale.",
                            Severity = Severity.Low,
                            Recommendation = "Adăugați întotdeauna atributul 'rel=\"noopener noreferrer\"' la toate link-urile care se deschid cu 'target=\"_blank\"'.",
                            Type = VulnerabilityType.SecurityMisconfiguration,
                            DetectedAt = DateTime.UtcNow
                        });
                    }
                }
            }

            // 4. Verifică script-uri încărcate prin HTTP
            var scripts = document.DocumentNode.SelectNodes("//script[@src]");
            if (scripts != null)
            {
                foreach (var script in scripts)
                {
                    var src = script.GetAttributeValue("src", "");
                    if (src.StartsWith("http://"))
                    {
                        scan.Vulnerabilities.Add(new Vulnerability
                        {
                            Title = "Script încărcat printr-o conexiune nesecurizată",
                            Description = $"Script-ul de la adresa '{src}' este încărcat prin HTTP. Acesta poate fi interceptat și modificat de un atacator (MitM).",
                            Severity = Severity.High,
                            Recommendation = "Încărcați toate resursele externe, inclusiv script-urile, folosind exclusiv conexiuni securizate HTTPS.",
                            Type = VulnerabilityType.SensitiveDataExposure,
                            DetectedAt = DateTime.UtcNow
                        });
                    }
                }
            }

            // Notă: Verificările pentru antete (Headers) necesită o altă abordare
            // și nu sunt incluse în această logică de parsare HTML.
        }

        private async Task<string> CreateReport(Scan scan)
        {
            if (scan == null) return "Raport invalid.";

            var reportHtml = $@"
                <h1>Raport de Vulnerabilități</h1>
                <h2>Detalii Scanare</h2>
                <p><strong>Aplicație:</strong> {scan.Application?.Name ?? "N/A"}</p>
                <p><strong>URL:</strong> {scan.Application?.Description ?? "N/A"}</p>
                <p><strong>Data:</strong> {scan.EndedAt:dd.MM.yyyy HH:mm}</p>
                <hr>
                <h2>Vulnerabilități Găsite ({scan.Vulnerabilities.Count})</h2>
            ";

            if (scan.Vulnerabilities.Any())
            {
                reportHtml += "<table border='1' cellpadding='5' style='width:100%; border-collapse: collapse;'>";
                reportHtml += @"
                    <tr style='background-color:#f2f2f2;'>
                        <th>Titlu</th>
                        <th>Severitate</th>
                        <th>Descriere</th>
                        <th>Recomandare</th>
                    </tr>
                ";
                foreach (var v in scan.Vulnerabilities)
                {
                    reportHtml += $@"
                        <tr>
                            <td>{v.Title}</td>
                            <td>{v.Severity}</td>
                            <td>{v.Description}</td>
                            <td>{v.Recommendation}</td>
                        </tr>
                    ";
                }
                reportHtml += "</table>";
            }
            else
            {
                reportHtml += "<p>Nicio vulnerabilitate găsită.</p>";
            }

            return reportHtml;
        }

        private async Task<string> SaveReportToFile(string content)
        {
            var monthYear = DateTime.UtcNow.ToString("yyyy-MM");
            var uploadsFolder = Path.Combine("wwwroot", "uploads", "scans", monthYear);
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            var reportFileName = $"{Guid.NewGuid()}.html";
            var fullReportPath = Path.Combine(uploadsFolder, reportFileName);

            await File.WriteAllTextAsync(fullReportPath, content);

            return Path.Combine("uploads", "scans", monthYear, reportFileName);
        }
    }
}