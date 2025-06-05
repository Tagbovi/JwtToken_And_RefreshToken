using JwtRefreshToken101.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JwtRefreshToken101.Data
{
    public class JwtDbContext : IdentityDbContext
    {
        public JwtDbContext(DbContextOptions<JwtDbContext> options) : base(options) { }

        public DbSet<ApplicationUserDbModel>? ApplicationUserDb { get; set;}
    }
}
