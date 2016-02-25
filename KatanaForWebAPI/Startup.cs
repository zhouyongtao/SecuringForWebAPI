using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.OAuth;

[assembly: OwinStartup(typeof(KatanaForWebAPI.Startup))]
namespace KatanaForWebAPI
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {

        }
    }
}