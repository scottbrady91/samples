using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Azure.Documents;
using Microsoft.Azure.Documents.Client;

namespace DocumentDbTestRunner
{
    internal class Program
    {
        private const string EndpointUri = "";
        private const string AuthKeyOrResourceToken = "";
        private const string DatabaseName = "DocumentDbTestRunner";
        private const string CollectionName = "Test";

        private static void Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += UnhandledExceptionHandler;

            Console.WriteLine("DocumentDB Test Runner");
            Console.WriteLine("1 - Create Database");
            Console.WriteLine("2 - Create Collection");
            Console.WriteLine("3 - Create Document");
            Console.WriteLine("4 - Read Document");

            Console.WriteLine("0 - Clean And Exit");

            var readLine = Console.ReadLine();
            while (readLine != null)
            {
                switch (readLine)
                {
                    case "1":
                        CreateDatabase().GetAwaiter().GetResult();
                        break;
                    case "0":
                        return;
                }
                readLine = Console.ReadLine();
            }
        }

        private static async Task CreateDatabase()
        {
            using (var client = new DocumentClient(new Uri(EndpointUri), AuthKeyOrResourceToken))
            {
                try
                {
                    var response = await client.ReadDatabaseAsync(UriFactory.CreateDatabaseUri(DatabaseName));
                    Console.WriteLine("Database exists");
                }
                catch (DocumentClientException exception)
                {
                    if (exception.StatusCode == HttpStatusCode.NotFound)
                    {
                        ResourceResponse<Database> response = await client.CreateDatabaseAsync(new Database {Id = DatabaseName});
                        Console.WriteLine("Database created");
                    }
                    else
                    {
                        throw;
                    }
                }
            }
        }

        private static async Task Cleanup()
        {
            using (var client = new DocumentClient(new Uri(EndpointUri), AuthKeyOrResourceToken))
            {
                await client.DeleteDatabaseAsync(UriFactory.CreateDatabaseUri(DatabaseName));
            }
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
