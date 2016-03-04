using System;
using Microsoft.Owin;
using Owin;
using IdentityServer3.Core.Configuration;
using IdentityServer3ForWebAPI.Models;
using System.Security.Cryptography.X509Certificates;

[assembly: OwinStartup(typeof(IdentityServer3ForWebAPI.Startup))]
namespace IdentityServer3ForWebAPI
{
    public class Startup
    {
        /// <summary>
        /// 配置信息
        /// </summary>
        /// <param name="app"></param>
        public void Configuration(IAppBuilder app)
        {
            /*
            //默认路由
             app.UseIdentityServer(new IdentityServerOptions
             {
                 EnableWelcomePage = true,
                 SiteName = "Embedded IdentityServer",
                 //SigningCertificate = LoadCertificate(),
                 Factory = new IdentityServerServiceFactory().UseInMemoryUsers(Users.Get())
                                                             .UseInMemoryClients(Clients.Get())
                                                             .UseInMemoryScopes(Scopes.Get()),
                 RequireSsl = false
             });
             */

            //配置idsv服务端
            app.Map("/identity", options =>
            {
                options.UseIdentityServer(new IdentityServerOptions
                {
                    EnableWelcomePage = true,
                    SiteName = "Embedded IdentityServer",
                    //SigningCertificate = LoadCertificate(),
                    Factory = new IdentityServerServiceFactory().UseInMemoryUsers(Users.Get())
                                                                .UseInMemoryClients(Clients.Get())
                                                                .UseInMemoryScopes(Scopes.Get()),
                    RequireSsl = false
                });
            });
        }

        /// <summary>
        /// 配置X509证书
        /// </summary>
        /// <returns></returns>
        private X509Certificate2 LoadCertificate()
        {
            return new X509Certificate2(string.Format(@"{0}bin\idsrv3test.pfx", AppDomain.CurrentDomain.BaseDirectory), "idsrv3test");
        }
    }
}
