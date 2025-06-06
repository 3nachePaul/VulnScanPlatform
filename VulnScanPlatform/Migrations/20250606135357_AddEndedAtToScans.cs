using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnScanPlatform.Migrations
{
    /// <inheritdoc />
    public partial class AddEndedAtToScans : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "EndedAt",
                table: "Scans",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EndedAt",
                table: "Scans");
        }
    }
}
