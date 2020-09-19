using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace ScottBrady.Pem.Kestrel
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    // this does not work on Windows
                    /*const string certPem = @"-----BEGIN CERTIFICATE-----
MIIB3zCCAYWgAwIBAgIUImttQCULqkHxYbDivb1fzRNFYG8wCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDA5MTgxNDQyMzlaFw0yMTA5MTMx
NDQyMzlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAARwfxEb6RX+fwiz70spEdLTfK/ite5ZGfysbalM/ZlnUjWZ+Cwk+aEc
KkER2GWoZ6Fiw3PcOlQzY8dGHMdkkHhGo1MwUTAdBgNVHQ4EFgQUOYFYa+w94G7t
MGD3bpM3T04WAxswHwYDVR0jBBgwFoAUOYFYa+w94G7tMGD3bpM3T04WAxswDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAxX7N6e+2NfuwR70u3AX0
mx5ZP9uQhdrvOi8qDBHSMMoCIEQenUMtTfYfOU8FwT3WZO4S5JB5jvPg9hCnlXPj
NwaC
-----END CERTIFICATE-----";
                    const string eccPem = @"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP7n5rwD8HN7VUqcyYD5p+5jBNZQGkQEzoZ76tjXd2TmoAoGCCqGSM49
AwEHoUQDQgAEcH8RG+kV/n8Is+9LKRHS03yv4rXuWRn8rG2pTP2ZZ1I1mfgsJPmh
HCpBEdhlqGehYsNz3DpUM2PHRhzHZJB4Rg==
-----END EC PRIVATE KEY-----";
                    
                    webBuilder.ConfigureKestrel(options =>
                    {
                        options.ConfigureHttpsDefaults(adapterOptions =>
                        {
                            adapterOptions.ServerCertificate = X509Certificate2.CreateFromPem(certPem, eccPem);
                        });
                    });*/
                    
                    webBuilder.UseStartup<Startup>();
                });
    }
}
