using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Azure.Documents;
using Microsoft.Azure.Documents.Client;
using Microsoft.Azure.Documents.Linq;
using Newtonsoft.Json;

namespace DocumentDbTestRunner
{
    internal class Program
    {
        private const string EndpointUri = "";
        private const string AuthKeyOrResourceToken = "";
        private const string DatabaseId = "DocumentDbTestRunner";
        private const string CollectionId = "Test";

        private static DocumentClient client;

        private class Post
        {
            [JsonProperty(PropertyName = "id")]
            public string Title { get; set; }
            public string Category { get; set; }
            public List<string> Tags { get; set; }
            public DateTime PublishDate { get; set; }
        }

        private static void Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += UnhandledExceptionHandler;

            client = new DocumentClient(new Uri(EndpointUri), AuthKeyOrResourceToken);

            Console.WriteLine("DocumentDB Test Runner");
            Console.WriteLine("1 - Create Database");
            Console.WriteLine("2 - Create Collection");
            Console.WriteLine("3 - Create Document");
            Console.WriteLine("4 - Read Document");
            Console.WriteLine("5 - Query Documents Synchronously");
            Console.WriteLine("6 - Query Documents Asynchronously");
            Console.WriteLine("7 - Update Document");
            Console.WriteLine("8 - Upsert Document");
            Console.WriteLine("9 - Delete Document");
            Console.WriteLine("x - Stored Procedure");

            Console.WriteLine("0 - Clean And Exit");

            var readLine = Console.ReadLine();
            while (readLine != null)
            {
                switch (readLine)
                {
                    case "1":
                        CreateDatabase().Wait();
                        break;
                    case "2":
                        CreateContainer().Wait();
                        break;
                    case "3":
                        CreateDocument().Wait();
                        break;
                    case "4":
                        ReadSingleDocument().Wait();
                        break;
                    case "5":
                        QueryDocuments();
                        break;
                    case "6":
                        QueryDocumentsAsync().Wait();
                        break;
                    case "7":
                        UpdateDocument().Wait();
                        break;
                    case "8":
                        UpsertDocument().Wait();
                        break;
                    case "9":
                        DeleteDocument().Wait();
                        break;
                    case "x":
                        StoredProc().Wait();
                        break;
                    case "0":
                        Cleanup().Wait();
                        return;
                }
                Console.WriteLine("Complete");
                Console.Write("Next: ");
                readLine = Console.ReadLine();
            }
        }

        private static async Task CreateDatabase()
        {
            try
            {
                await client.ReadDatabaseAsync(UriFactory.CreateDatabaseUri(DatabaseId));
                Console.WriteLine("Database exists");
            }
            catch (DocumentClientException exception)
            {
                if (exception.StatusCode == HttpStatusCode.NotFound)
                {
                    await client.CreateDatabaseAsync(new Database { Id = DatabaseId });
                    Console.WriteLine("Database created");
                }
                else
                {
                    throw;
                }
            }
        }

        private static async Task CreateContainer()
        {
            try
            {
                await client.ReadDocumentCollectionAsync(UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId));
                Console.WriteLine("Collection exists");
            }
            catch (DocumentClientException exception)
            {
                if (exception.StatusCode == HttpStatusCode.NotFound)
                {
                    await
                        client.CreateDocumentCollectionAsync(UriFactory.CreateDatabaseUri(DatabaseId),
                            new DocumentCollection { Id = CollectionId });
                    Console.WriteLine("Collection created");
                }
                else
                {
                    throw;
                }
            }
        }

        private static async Task CreateDocument()
        {
            await
                client.CreateDocumentAsync(UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId),
                    new Post
                    {
                        Title = "Getting Started with the Azure DocumentDB .NET SDK",
                        Category = "Azure",
                        Tags = new List<string> { "Azure", "DocumentDB", "NoSQL" },
                        PublishDate = new DateTime(2016, 7, 5)
                    });
        }

        private static async Task ReadSingleDocument()
        {
            var stopwatch = Stopwatch.StartNew();

            var response = await client.ReadDocumentAsync(UriFactory.CreateDocumentUri(DatabaseId, CollectionId,
                "Getting Started with the Azure DocumentDB .NET SDK"));

            var post = JsonConvert.DeserializeObject<Post>(response.Resource.ToString());

            stopwatch.Stop();
            Console.WriteLine($"Completed in {stopwatch.ElapsedMilliseconds}ms");

            if (post?.Title != null)
            {
                Console.WriteLine("Read document successfully");
            }
        }

        private static void QueryDocuments()
        {
            var stopwatch = Stopwatch.StartNew();

            IQueryable<Post> queryable =
                client.CreateDocumentQuery<Post>(UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId))
                    .Where(x => x.Category == "Azure");

            List<Post> posts = queryable.ToList();

            stopwatch.Stop();
            Console.WriteLine($"Completed in {stopwatch.ElapsedMilliseconds}ms");

            foreach (var post in posts)
            {
                Console.WriteLine(post.Title);
            }
        }

        private static async Task QueryDocumentsAsync()
        {
            var stopwatch = Stopwatch.StartNew();

            string continuationToken = null;

            do
            {
                var queryable = client.CreateDocumentQuery<Post>(UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId), new FeedOptions { MaxItemCount = 1, RequestContinuation = continuationToken })
                      .Where(x => x.Category == "Azure").AsDocumentQuery();

                var feedResponse = await queryable.ExecuteNextAsync<Post>();
                continuationToken = feedResponse.ResponseContinuation;

                foreach (var post in feedResponse.ToList())
                {
                    Console.WriteLine(post.Title);
                }

            } while (continuationToken != null);

            stopwatch.Stop();
            Console.WriteLine($"Completed in {stopwatch.ElapsedMilliseconds}ms");
        }

        private static async Task UpdateDocument()
        {
            await
                client.ReplaceDocumentAsync(
                    UriFactory.CreateDocumentUri(DatabaseId, CollectionId, "Getting Started with the Azure DocumentDB .NET SDK"),
                    new Post
                    {
                        Title = "Getting Started with the Azure DocumentDB .NET SDK",
                        Category = "Azure",
                        Tags =
                            new List<string>
                            {
                                "Azure",
                                "DocumentDB",
                                "NoSQL",
                                DateTime.UtcNow.ToString(CultureInfo.InvariantCulture)
                            },
                        PublishDate = new DateTime(2016, 7, 5)
                    });
        }

        private static async Task UpsertDocument()
        {
            await client.UpsertDocumentAsync(UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId), new Post
            {
                Title = "Getting Started with the Azure DocumentDB .NET SDK",
                Category = "Azure",
                Tags =
                    new List<string>
                    {
                        "Azure",
                        "DocumentDB",
                        "NoSQL",
                        DateTime.UtcNow.ToString(CultureInfo.InvariantCulture) + " Upserted!"
                    },
                PublishDate = new DateTime(2016, 7, 5)
            });
        }

        private static async Task StoredProc()
        {
            const string function = @"function(id) {
    var context = getContext();
    var collection = context.getCollection();
    var collectionLink = collection.getSelfLink();
    var response = context.getResponse();

    var query = 'SELECT * FROM x WHERE x.id = ""' + id + '""';

    collection.queryDocuments(collectionLink, query, { }, function(err, documents) {
        if(!documents || !documents.length) response.setBody('No documents were found.');
        else response.setBody(JSON.stringify(documents));
    });
}";

            await client.UpsertStoredProcedureAsync(UriFactory.CreateDocumentCollectionUri(DatabaseId, CollectionId),
                new StoredProcedure {Id = "TestReadStoredProc", Body = function});

            var response = await client.ExecuteStoredProcedureAsync<string>(UriFactory.CreateStoredProcedureUri(DatabaseId, CollectionId,
                "TestReadStoredProc"), "Getting Started with the Azure DocumentDB .NET SDK");

            var posts = JsonConvert.DeserializeObject<List<Post>>(response.Response);
            Console.WriteLine($"Found {posts.Count}");
        }

        private static async Task DeleteDocument()
        {
            await
                client.DeleteDocumentAsync(UriFactory.CreateDocumentUri(DatabaseId, CollectionId,
                    "Getting Started with the Azure DocumentDB .NET SDK"));
        }

        private static async Task Cleanup()
        {
            await client.DeleteDatabaseAsync(UriFactory.CreateDatabaseUri(DatabaseId));
        }

        private static void UnhandledExceptionHandler(object sender, UnhandledExceptionEventArgs e)
        {
            Console.WriteLine(e.ExceptionObject.ToString());
            Console.WriteLine("Press Enter to exit...");
            Console.ReadLine();
            Environment.Exit(1);
        }
    }
}
