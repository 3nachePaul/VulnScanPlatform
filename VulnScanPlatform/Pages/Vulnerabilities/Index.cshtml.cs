using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnScanPlatform.Models;
using Newtonsoft.Json;

namespace VulnScanPlatform.Pages.Vulnerabilities
{
    public class IndexModel : PageModel
    {
        private readonly ApplicationDbContext _context;

        public IndexModel(ApplicationDbContext context)
        {
            _context = context;
        }

        public List<VulnerabilityPostDto> Posts { get; set; } = new();
        public string CurrentUserId { get; set; }

        [BindProperty(SupportsGet = true)]
        public string SortBy { get; set; } = "recent";

        public async Task OnGetAsync()
        {
            CurrentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var query = _context.VulnerabilityPosts
                .Include(p => p.PostedBy)
                .Include(p => p.Votes)
                .Where(p => p.IsApproved);

            // Sortare
            query = SortBy switch
            {
                "popular" => query.OrderByDescending(p => p.UpvoteCount).ThenByDescending(p => p.PostedAt),
                _ => query.OrderByDescending(p => p.PostedAt)
            };

            var posts = await query.ToListAsync();

            // Transform în DTO
            Posts = posts.Select(p => new VulnerabilityPostDto
            {
                Id = p.Id,
                Title = p.Title,
                Description = p.Description,
                VulnerabilityCount = p.VulnerabilityCount,
                CriticalCount = p.CriticalCount,
                HighCount = p.HighCount,
                MediumCount = p.MediumCount,
                LowCount = p.LowCount,
                PostedByName = p.PostedBy.FullName,
                PostedByEmail = p.PostedBy.Email,
                PostedAt = p.PostedAt,
                UpvoteCount = p.UpvoteCount,
                HasUserVoted = CurrentUserId != null && p.Votes.Any(v => v.UserId == CurrentUserId),
                Vulnerabilities = string.IsNullOrEmpty(p.VulnerabilitiesJson)
                    ? new List<VulnerabilityDto>()
                    : JsonConvert.DeserializeObject<List<VulnerabilityDto>>(p.VulnerabilitiesJson)
            }).ToList();
        }

        public async Task<IActionResult> OnPostVoteAsync(int postId)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return new JsonResult(new { success = false, message = "Trebuie să fii autentificat pentru a vota." });
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var post = await _context.VulnerabilityPosts
                .Include(p => p.Votes)
                .FirstOrDefaultAsync(p => p.Id == postId);

            if (post == null)
            {
                return new JsonResult(new { success = false, message = "Postarea nu a fost găsită." });
            }

            var existingVote = post.Votes.FirstOrDefault(v => v.UserId == userId);

            if (existingVote != null)
            {
                // Retrage votul
                _context.VulnerabilityPostVotes.Remove(existingVote);
                post.UpvoteCount--;
            }
            else
            {
                // Adaugă vot
                var vote = new VulnerabilityPostVote
                {
                    PostId = postId,
                    UserId = userId,
                    VotedAt = DateTime.UtcNow
                };
                _context.VulnerabilityPostVotes.Add(vote);
                post.UpvoteCount++;
            }

            await _context.SaveChangesAsync();

            return new JsonResult(new
            {
                success = true,
                upvoteCount = post.UpvoteCount,
                hasVoted = existingVote == null
            });
        }
    }

    public class VulnerabilityPostDto
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public int VulnerabilityCount { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public string PostedByName { get; set; }
        public string PostedByEmail { get; set; }
        public DateTime PostedAt { get; set; }
        public int UpvoteCount { get; set; }
        public bool HasUserVoted { get; set; }
        public List<VulnerabilityDto> Vulnerabilities { get; set; } = new();
    }

    public class VulnerabilityDto
    {
        public string Title { get; set; }
        public string Description { get; set; }
        public string Severity { get; set; }
        public string Type { get; set; }
        public string Impact { get; set; }
        public string Recommendation { get; set; }
    }
}