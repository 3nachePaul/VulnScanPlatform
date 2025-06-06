using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using HtmlAgilityPack;
using VulnScanPlatform.Hubs;
using VulnScanPlatform.Models;

namespace VulnScanPlatform.Services
{
    public class ScanService : IScanService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ILogger<ScanService> _logger;
        private readonly IHubContext<ScanHub> _hubContext;

        public ScanService(IServiceScopeFactory scopeFactory, ILogger<ScanService> logger, IHubContext<ScanHub> hubContext)
        {
            _scopeFactory = scopeFactory;
            _logger = logger;
            _hubContext = hubContext;
        }

        public async Task ProcessScanAsync(int scanId)
        {
            using var scope = _scopeFactory.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var scan = await context.Scans.Include(s => s.Report).FirstOrDefaultAsync(s => s.Id == scanId);
            if (scan == null || scan.Report == null)
            {
                _logger.LogError("Scan or associated report not found for ScanId: {ScanId}", scanId);
                return;
            }

            var groupName = $"Report-{scan.Report.Id}";
            var vulnerabilitiesFound = new List<Vulnerability>();

            try
            {
                scan.Status = ScanStatus.InProgress;
                await context.SaveChangesAsync();
                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "InProgress", "Scanarea a început: Se încarcă fișierul HTML...");

                var htmlDoc = new HtmlDocument();
                htmlDoc.LoadHtml(scan.FileContent);
                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "InProgress", "Progres: Fișierul a fost încărcat și parsat.");

                // Rulează verificările
                await CheckSecurityHeaders(htmlDoc, scan, groupName, vulnerabilitiesFound);
                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "InProgress", "Progres: S-au verificat antetele de securitate.");

                await CheckInsecureForms(htmlDoc, scan, groupName, vulnerabilitiesFound);
                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "InProgress", "Progres: S-au verificat formularele.");

                await CheckInsecurePasswordInputs(htmlDoc, scan, groupName, vulnerabilitiesFound);
                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "InProgress", "Progres: S-au verificat câmpurile de parolă.");

                await CheckExternalLinks(htmlDoc, scan, groupName, vulnerabilitiesFound);
                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "InProgress", "Progres: S-au verificat link-urile externe.");

                await CheckInsecureScripts(htmlDoc, scan, groupName, vulnerabilitiesFound);
                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "InProgress", "Progres: S-au verificat script-urile.");

                // Finalizează scanarea
                scan.Status = ScanStatus.Completed;
                scan.CompletedAt = DateTime.UtcNow;
                scan.Report.Content = $"Analiza s-a finalizat. Au fost identificate {vulnerabilitiesFound.Count} vulnerabilități.";
                context.Vulnerabilities.AddRange(vulnerabilitiesFound);
                await context.SaveChangesAsync();

                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "Completed", scan.Report.Content);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing scan {ScanId}", scanId);
                scan.Status = ScanStatus.Failed;
                await context.SaveChangesAsync();
                await _hubContext.Clients.Group(groupName).SendAsync("ReceiveStatusUpdate", "Failed", "Scanarea a eșuat. Verificați log-urile.");
            }
        }

        private async Task CheckSecurityHeaders(HtmlDocument doc, Scan scan, string groupName, List<Vulnerability> found)
        {
            var headers = new Dictionary<string, (Severity, string, string)>
            {
                { "Content-Security-Policy", (Severity.High, "Protejează împotriva atacurilor XSS și a altor injecții de cod.", "Implementați un antet CSP strict care definește sursele de încredere pentru conținut.") },
                { "X-Content-Type-Options", (Severity.Low, "Previne atacurile de tip MIME-sniffing.", "Adăugați antetul 'X-Content-Type-Options: nosniff'.") },
                { "X-Frame-Options", (Severity.Medium, "Protejează împotriva atacurilor de tip clickjacking.", "Adăugați antetul 'X-Frame-Options: DENY' sau 'SAMEORIGIN'.") },
                { "Strict-Transport-Security", (Severity.Medium, "Forțează browserul să comunice doar prin HTTPS.", "Adăugați antetul 'Strict-Transport-Security' cu o durată corespunzătoare.") }
            };

            foreach (var header in headers)
            {
                if (doc.DocumentNode.SelectSingleNode($"//meta[@http-equiv='{header.Key}']") == null)
                {
                    var vulnerability = new Vulnerability { Title = $"Antetul de securitate '{header.Key}' lipsește", Description = $"Antetul HTTP '{header.Key}' nu este prezent, ceea ce poate expune aplicația la riscuri.", Impact = header.Value.Item2, Recommendation = header.Value.Item3, Severity = header.Value.Item1, ScanId = scan.Id, Status = VulnerabilityStatus.Open, Type = VulnerabilityType.SecurityMisconfiguration };
                    found.Add(vulnerability);
                    await _hubContext.Clients.Group(groupName).SendAsync("ReceiveNewVulnerability", vulnerability);
                }
            }
        }

        private async Task CheckInsecureForms(HtmlDocument doc, Scan scan, string groupName, List<Vulnerability> found)
        {
            var forms = doc.DocumentNode.SelectNodes("//form[translate(@method, 'GET', 'get')='get']");
            if (forms != null)
            {
                foreach (var form in forms)
                {
                    var vulnerability = new Vulnerability { Title = "Formular nesecurizat (metoda GET)", Description = "Acest formular folosește metoda GET pentru a trimite date. Datele sensibile pot fi expuse în URL, în istoricul browser-ului și în log-urile server-ului.", Impact = "Datele trimise prin formular, inclusiv cele potențial sensibile, pot fi interceptate sau vizualizate de terți neautorizați.", Recommendation = "Folosiți metoda POST pentru toate formularele care manipulează date, în special cele sensibile.", Severity = Severity.Low, ScanId = scan.Id, Status = VulnerabilityStatus.Open, Type = VulnerabilityType.InsecureConfiguration };
                    found.Add(vulnerability);
                    await _hubContext.Clients.Group(groupName).SendAsync("ReceiveNewVulnerability", vulnerability);
                }
            }
        }

        private async Task CheckInsecurePasswordInputs(HtmlDocument doc, Scan scan, string groupName, List<Vulnerability> found)
        {
            var passwordInputs = doc.DocumentNode.SelectNodes("//input[@type='password']");
            if (passwordInputs != null)
            {
                foreach (var input in passwordInputs)
                {
                    if (input.GetAttributeValue("autocomplete", "").ToLower() != "new-password")
                    {
                        var vulnerability = new Vulnerability { Title = "Câmp de parolă nesecurizat", Description = "Câmpul de parolă nu are atributul 'autocomplete=\"new-password\"', ceea ce poate duce la salvarea parolelor în mod nesigur de către managerii de parole din browser.", Impact = "Managerii de parole pot sugera sau autocompleta parole în moduri care pot fi interceptate de script-uri malițioase.", Recommendation = "Adăugați atributul 'autocomplete=\"new-password\"' la toate câmpurile de parolă pentru a spori securitatea.", Severity = Severity.Medium, ScanId = scan.Id, Status = VulnerabilityStatus.Open, Type = VulnerabilityType.InsecureConfiguration };
                        found.Add(vulnerability);
                        await _hubContext.Clients.Group(groupName).SendAsync("ReceiveNewVulnerability", vulnerability);
                    }
                }
            }
        }

        private async Task CheckExternalLinks(HtmlDocument doc, Scan scan, string groupName, List<Vulnerability> found)
        {
            var links = doc.DocumentNode.SelectNodes("//a[@target='_blank']");
            if (links != null)
            {
                foreach (var link in links)
                {
                    var rel = link.GetAttributeValue("rel", "").ToLower();
                    if (!rel.Contains("noopener") || !rel.Contains("noreferrer"))
                    {
                        var vulnerability = new Vulnerability { Title = "Link extern nesecurizat (risc de tabnabbing)", Description = $"Link-ul către '{link.GetAttributeValue("href", "#")}' se deschide într-un tab nou fără 'rel=\"noopener noreferrer\"'.", Impact = "Pagina nouă poate avea control parțial asupra paginii originale (ex: o poate redirecționa către un site de phishing), ceea ce poate induce în eroare utilizatorul.", Recommendation = "Adăugați întotdeauna atributul 'rel=\"noopener noreferrer\"' la toate link-urile care se deschid cu 'target=\"_blank\"'.", Severity = Severity.Low, ScanId = scan.Id, Status = VulnerabilityStatus.Open, Type = VulnerabilityType.InsecureConfiguration };
                        found.Add(vulnerability);
                        await _hubContext.Clients.Group(groupName).SendAsync("ReceiveNewVulnerability", vulnerability);
                    }
                }
            }
        }

        private async Task CheckInsecureScripts(HtmlDocument doc, Scan scan, string groupName, List<Vulnerability> found)
        {
            var scripts = doc.DocumentNode.SelectNodes("//script[@src]");
            if (scripts != null)
            {
                foreach (var script in scripts)
                {
                    var src = script.GetAttributeValue("src", "");
                    if (src.StartsWith("http://"))
                    {
                        var vulnerability = new Vulnerability { Title = "Script încărcat printr-o conexiune nesecurizată", Description = $"Script-ul de la adresa '{src}' este încărcat prin HTTP.", Impact = "Un atacator aflat în aceeași rețea (Man-in-the-Middle) ar putea intercepta și modifica acest script pentru a injecta cod malițios în pagina dumneavoastră.", Recommendation = "Încărcați toate resursele externe, inclusiv script-urile, folosind exclusiv conexiuni securizate HTTPS.", Severity = Severity.High, ScanId = scan.Id, Status = VulnerabilityStatus.Open, Type = VulnerabilityType.InsecureConfiguration };
                        found.Add(vulnerability);
                        await _hubContext.Clients.Group(groupName).SendAsync("ReceiveNewVulnerability", vulnerability);
                    }
                }
            }
        }
    }
}