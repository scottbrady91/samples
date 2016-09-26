using System.Linq;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace ScottBrady91.BlogExampleCode.EntityFrameworkCoreInMemoryTesting
{
    public class SqliteDatabaseProvider
    {
        private readonly DbContextOptions<TestDbContext> options;

        public SqliteDatabaseProvider()
        {
            var connectionStringBuilder = new SqliteConnectionStringBuilder { DataSource = ":memory:" };
            var connectionString = connectionStringBuilder.ToString();
            var connection = new SqliteConnection(connectionString);
            
            var builder = new DbContextOptionsBuilder<TestDbContext>();
            builder.UseSqlite(connection);
            options = builder.Options;

            using (var context = new TestDbContext(options))
            {
                context.Database.OpenConnection();
                context.Database.EnsureCreated();
            }
        }

        [Fact]
        public void CanAddEntity()
        {
            var testEntity = new TestEntity { Id = 1, Name = "Test Entity" };

            using (var context = new TestDbContext(options))
            {
                context.TestEntities.Add(testEntity);
                context.SaveChanges();
            }

            TestEntity foundEntity;
            using (var context = new TestDbContext(options))
            {
                foundEntity = context.TestEntities.FirstOrDefault(x => x.Id == testEntity.Id);
            }

            Assert.NotNull(foundEntity);
            Assert.Equal(testEntity.Name, foundEntity.Name);
        }
    }
}
