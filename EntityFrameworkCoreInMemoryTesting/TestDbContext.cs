using Microsoft.EntityFrameworkCore;

namespace EfCoreInMemory;

public class TestDbContext : DbContext
{
    public TestDbContext(DbContextOptions options) : base(options) { }

    public DbSet<TestEntity> TestEntities { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TestEntity>(entity =>
        {
            entity.ToTable("TestEntites");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Name).HasMaxLength(200).IsRequired();
        });

        base.OnModelCreating(modelBuilder);
    }
}
    
public class TestEntity
{
    public int Id { get; set; }

    public string Name { get; set; }
}