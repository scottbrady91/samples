using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EfCoreInMemory;

public class EfCoreInMemory
{
    [Fact]
    public async Task TestWithInMemory()
    {
        var builder = new DbContextOptionsBuilder<TestDbContext>();
        builder.UseInMemoryDatabase("test_db");
        DbContextOptions<TestDbContext> options = builder.Options;

        await DatabaseTest(options);
    }

    [Fact]
    public async Task TestWithSqliteInMemory()
    {
        var connectionStringBuilder = new SqliteConnectionStringBuilder { DataSource = ":memory:" };
        var connectionString = connectionStringBuilder.ToString();
        var connection = new SqliteConnection(connectionString);

        var builder = new DbContextOptionsBuilder<TestDbContext>();
        builder.UseSqlite(connection);
        DbContextOptions<TestDbContext> options = builder.Options;

        await using (var context = new TestDbContext(options))
        {
            await context.Database.OpenConnectionAsync();
            await context.Database.EnsureCreatedAsync();
        }

        await DatabaseTest(options);
    }

    private async Task DatabaseTest(DbContextOptions<TestDbContext> options)
    {
        var testEntity = new TestEntity { Id = 1, Name = "Test Entity" };

        await using (var context = new TestDbContext(options))
        {
            context.TestEntities.Add(testEntity);
            await context.SaveChangesAsync();
        }

        TestEntity foundEntity;
        await using (var context = new TestDbContext(options))
        {
            foundEntity = await context.TestEntities.FirstOrDefaultAsync(x => x.Id == testEntity.Id);
        }

        Assert.NotNull(foundEntity);
        Assert.Equal(testEntity.Name, foundEntity.Name);
    }
}