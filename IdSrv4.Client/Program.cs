using IdentityModel.Client;
using System;
using System.Net.Http;
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
            var client = new TokenClient(disco.TokenEndpoint, "client_credentials_jwt_grant", "123456");
            var response = await client.RequestClientCredentialsAsync("api");
            if (response.IsError)
            {
                Console.WriteLine(response.Error);
                Console.Read();
            }
            Console.WriteLine(response.Json);
            //call api
            var http = new HttpClient();
            http.SetBearerToken(response.AccessToken);
            var message = await http.GetAsync("http://localhost:17181/api/values/1");
            if (!message.IsSuccessStatusCode)
            {
                Console.WriteLine(message.ReasonPhrase);
                Console.Read();
            }
            Console.WriteLine(message.Content.ReadAsStringAsync().Result);
        }
    }
}