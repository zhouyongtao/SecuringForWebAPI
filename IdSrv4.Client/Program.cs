using IdentityModel.Client;
using System;
using System.Threading.Tasks;

namespace IdSrv4.Client
{
    class Program
    {
        static void Main(string[] args)
        {
            Task.Run(() =>
            {
                return Run();
            });
            Console.ReadLine();
        }

        public static async Task Run()
        {
            var disco = await DiscoveryClient.GetAsync("http://localhost:5000");
            //jwt
            var client = new TokenClient(disco.TokenEndpoint, "client_2", "123456");
            var response = await client.RequestClientCredentialsAsync("order");
            if (response.IsError)
            {
                Console.WriteLine(response.Error);
                return;
            }
            Console.WriteLine(response.Json);
        }
    }
}