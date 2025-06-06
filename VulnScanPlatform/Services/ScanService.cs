// Services/ScanService.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.RegularExpressions;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Services
{
    public class ScanService : IScanService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<ScanService> _logger;

        public ScanService(ApplicationDbContext context, ILogger<ScanService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task ProcessScanAsync(int scanId)
        {
            try
            {
                var scan = await _context.Scans
                    .Include(s => s.Application)
                    .Include(s => s.Report)
                    .FirstOrDefaultAsync(s => s.Id == scanId);

                if (scan == null)
                {
                    _logger.LogError("Scan {ScanId} not found", scanId);
                    return;
                }

                // Update scan status
                scan.Status = ScanStatus.InProgress;
                await _context.SaveChangesAsync();

                _logger.LogInformation("Starting scan {ScanId} for application {AppName}",
                    scanId, scan.Application.Name);

                // Analyze HTML content
                var vulnerabilities = await AnalyzeHtmlContent(scan.FileContent);

                // Save vulnerabilities
                foreach (var vuln in vulnerabilities)
                {
                    vuln.ScanId = scanId;
                    _context.Vulnerabilities.Add(vuln);
                }

                // Update scan status
                scan.Status = ScanStatus.Completed;
                scan.CompletedAt = DateTime.UtcNow;

                // Update report with results
                if (scan.Report != null)
                {
                    scan.Report.Content = GenerateReportContent(scan, vulnerabilities);
                }

                await _context.SaveChangesAsync();

                _logger.LogInformation("Scan {ScanId} completed with {VulnCount} vulnerabilities",
                    scanId, vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing scan {ScanId}", scanId);

                var scan = await _context.Scans.FindAsync(scanId);
                if (scan != null)
                {
                    scan.Status = ScanStatus.Failed;
                    await _context.SaveChangesAsync();
                }
            }
        }

        private async Task<List<Vulnerability>> AnalyzeHtmlContent(string htmlContent)
        {
            var vulnerabilities = new List<Vulnerability>();

            // SQL Injection detection in forms
            var formPattern = @"<form[^>]*>(.*?)</form>";
            var formMatches = Regex.Matches(htmlContent, formPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);

            foreach (Match formMatch in formMatches)
            {
                var formContent = formMatch.Value;

                // Check for SQL injection vulnerabilities
                if (ContainsSqlInjectionPatterns(formContent))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Title = "Potențial SQL Injection în formular",
                        Description = "Formularul pare să construiască query-uri SQL direct din input-ul utilizatorului.",
                        Type = VulnerabilityType.SqlInjection,
                        Severity = Severity.Critical,
                        Impact = "Un atacator poate executa comenzi SQL arbitrare și poate accesa sau modifica date sensibile.",
                        Recommendation = "Folosiți parametri pregătiți (prepared statements) și validați toate input-urile.",
                        DetectedAt = DateTime.UtcNow
                    });
                }
            }

            // XSS detection
            if (ContainsXssPatterns(htmlContent))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Potențial Cross-Site Scripting (XSS)",
                    Description = "Conținutul HTML conține pattern-uri care pot permite injectarea de script-uri malițioase.",
                    Type = VulnerabilityType.XSS,
                    Severity = Severity.High,
                    Impact = "Atacatorii pot executa JavaScript în browserul victimei și pot fura cookie-uri sau date sensibile.",
                    Recommendation = "Sanitizați toate output-urile și folosiți Content Security Policy (CSP).",
                    DetectedAt = DateTime.UtcNow
                });
            }

            // CSRF detection
            var hasCSRFProtection = htmlContent.Contains("csrf") || htmlContent.Contains("token") || htmlContent.Contains("RequestVerificationToken");
            if (formMatches.Count > 0 && !hasCSRFProtection)
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Lipsă protecție CSRF",
                    Description = "Formularele nu par să aibă protecție împotriva atacurilor Cross-Site Request Forgery.",
                    Type = VulnerabilityType.CSRF,
                    Severity = Severity.Medium,
                    Impact = "Un atacator poate forța utilizatorii autentificați să execute acțiuni nedorite.",
                    Recommendation = "Implementați token-uri CSRF pentru toate formularele care modifică date.",
                    DetectedAt = DateTime.UtcNow
                });
            }

            // Sensitive data exposure
            if (ContainsSensitiveDataPatterns(htmlContent))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Expunere potențială de date sensibile",
                    Description = "HTML-ul conține pattern-uri care sugerează expunerea de date sensibile.",
                    Type = VulnerabilityType.SensitiveDataExposure,
                    Severity = Severity.High,
                    Impact = "Date sensibile precum parole sau informații personale pot fi vizibile.",
                    Recommendation = "Nu includeți date sensibile în HTML. Folosiți HTTPS și criptați datele sensibile.",
                    DetectedAt = DateTime.UtcNow
                });
            }

            // Missing security headers
            if (!htmlContent.Contains("X-Frame-Options") && !htmlContent.Contains("frame-ancestors"))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Header de securitate lipsă: X-Frame-Options",
                    Description = "Pagina poate fi încărcată într-un iframe, permițând atacuri clickjacking.",
                    Type = VulnerabilityType.Other,
                    Severity = Severity.Low,
                    Impact = "Pagina poate fi supusă atacurilor de tip clickjacking.",
                    Recommendation = "Adăugați header-ul X-Frame-Options: SAMEORIGIN sau folosiți CSP frame-ancestors.",
                    DetectedAt = DateTime.UtcNow
                });
            }

            return vulnerabilities;
        }

        private bool ContainsSqlInjectionPatterns(string content)
        {
            var patterns = new[]
            {
                @"SELECT\s+.*\s+FROM",
                @"INSERT\s+INTO",
                @"UPDATE\s+.*\s+SET",
                @"DELETE\s+FROM",
                @"DROP\s+TABLE",
                @";\s*--",
                @"UNION\s+SELECT",
                @"OR\s+1\s*=\s*1",
                @"'\s+OR\s+'",
                "mysql_query",
                "mysqli_query",
                "pg_query"
            };

            return patterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        private bool ContainsXssPatterns(string content)
        {
            var patterns = new[]
            {
                @"<script[^>]*>",
                @"javascript:",
                @"on\w+\s*=",
                @"eval\s*\(",
                @"expression\s*\(",
                @"document\.write",
                @"document\.cookie",
                @"innerHTML\s*=",
                @"\.html\(\)",
                @"<iframe",
                @"<object",
                @"<embed"
            };

            return patterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        private bool ContainsSensitiveDataPatterns(string content)
        {
            var patterns = new[]
            {
                @"password\s*[:=]",
                @"api[_-]?key\s*[:=]",
                @"secret\s*[:=]",
                @"token\s*[:=]",
                @"\b\d{16}\b", // Credit card pattern
                @"\b\d{3}-\d{2}-\d{4}\b", // SSN pattern
                @"private[_-]?key",
                @"BEGIN\s+(RSA|DSA|EC)\s+PRIVATE\s+KEY"
            };

            return patterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        private string GenerateReportContent(Scan scan, List<Vulnerability> vulnerabilities)
        {
            var criticalCount = vulnerabilities.Count(v => v.Severity == Severity.Critical);
            var highCount = vulnerabilities.Count(v => v.Severity == Severity.High);
            var mediumCount = vulnerabilities.Count(v => v.Severity == Severity.Medium);
            var lowCount = vulnerabilities.Count(v => v.Severity == Severity.Low);

            var html = $@"
                <h3>Raport de Scanare pentru {scan.Application.Name}</h3>
                <p>Data analizei: {DateTime.Now:dd MMMM yyyy, HH:mm}</p>
                <p>Fișier analizat: {scan.FileName}</p>
                
                <h4>Sumar Executiv</h4>
                <p>Scanarea automată a identificat <strong>{vulnerabilities.Count} vulnerabilități potențiale</strong> în aplicație.</p>
                
                <h4>Distribuție Severitate</h4>
                <table class='table table-bordered'>
                    <tr>
                        <th>Severitate</th>
                        <th>Număr</th>
                        <th>Procent</th>
                    </tr>
                    <tr class='table-danger'>
                        <td><i class='fas fa-exclamation-circle'></i> Critică</td>
                        <td>{criticalCount}</td>
                        <td>{(criticalCount * 100.0 / Math.Max(vulnerabilities.Count, 1)):F1}%</td>
                    </tr>
                    <tr class='table-warning'>
                        <td><i class='fas fa-exclamation-triangle'></i> Înaltă</td>
                        <td>{highCount}</td>
                        <td>{(highCount * 100.0 / Math.Max(vulnerabilities.Count, 1)):F1}%</td>
                    </tr>
                    <tr class='table-info'>
                        <td><i class='fas fa-info-circle'></i> Medie</td>
                        <td>{mediumCount}</td>
                        <td>{(mediumCount * 100.0 / Math.Max(vulnerabilities.Count, 1)):F1}%</td>
                    </tr>
                    <tr class='table-secondary'>
                        <td><i class='fas fa-info'></i> Scăzută</td>
                        <td>{lowCount}</td>
                        <td>{(lowCount * 100.0 / Math.Max(vulnerabilities.Count, 1)):F1}%</td>
                    </tr>
                </table>
                
                <h4>Vulnerabilități Detectate</h4>";

            foreach (var vuln in vulnerabilities.OrderBy(v => v.Severity))
            {
                var severityClass = vuln.Severity switch
                {
                    Severity.Critical => "danger",
                    Severity.High => "warning",
                    Severity.Medium => "info",
                    _ => "secondary"
                };

                html += $@"
                    <div class='card mb-3 border-{severityClass}'>
                        <div class='card-header bg-{severityClass} text-white'>
                            <h5 class='mb-0'>{vuln.Title}</h5>
                        </div>
                        <div class='card-body'>
                            <p><strong>Tip:</strong> {vuln.Type}</p>
                            <p><strong>Severitate:</strong> {vuln.Severity}</p>
                            <p><strong>Descriere:</strong> {vuln.Description}</p>
                            <p><strong>Impact:</strong> {vuln.Impact}</p>
                            <p><strong>Recomandare:</strong> {vuln.Recommendation}</p>
                        </div>
                    </div>";
            }

            html += @"
                <h4>Recomandări Generale</h4>
                <ol>
                    <li>Prioritizați remedierea vulnerabilităților critice și înalte</li>
                    <li>Implementați un proces de code review pentru schimbările viitoare</li>
                    <li>Folosiți tool-uri de analiză statică în procesul de development</li>
                    <li>Efectuați teste de penetrare regulate</li>
                    <li>Mențineți toate dependențele actualizate</li>
                </ol>";

            return html;
        }
    }
}

