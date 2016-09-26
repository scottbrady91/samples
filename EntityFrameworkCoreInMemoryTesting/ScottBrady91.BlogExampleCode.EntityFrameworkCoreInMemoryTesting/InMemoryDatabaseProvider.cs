using System.Linq;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace ScottBrady91.BlogExampleCode.EntityFrameworkCoreInMemoryTesting
{
    public class InMemoryDatabaseProvider
    {
        private readonly DbContextOptions<TestDbContext> options;

        public InMemoryDatabaseProvider()
        {
            var builder = new DbContextOptionsBuilder<TestDbContext>();
            builder.UseInMemoryDatabase();
            options = builder.Options;
        }

        [Fact]
        public void CanAddEntity()
        {
            var testEntity = new TestEntity {Id = 1, Name = "Test Entity"};

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
