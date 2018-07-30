using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdSrv4.HostSrv.IdSrv;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace IdSrv4.HostSrv
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });
            //获得证书文件
            var filePath = Path.Combine(AppContext.BaseDirectory, Configuration["Certs:Path"]);
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("Signing Certificate is missing!");
            }
            var x509Cert = new X509Certificate2(filePath, Configuration["Certs:Pwd"]);
            var credential = new SigningCredentials(new X509SecurityKey(x509Cert), "ES256");

            // configure identity server with in-memory stores, keys, clients and scopes
            services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
             //.AddDeveloperSigningCredential()
             //.AddDeveloperSigningCredential(persistKey: true, filename: "rsakey.rsa")、
             //   .AddSigningCredential(x509Cert)
             .AddSigningCredential(credential)
            .AddInMemoryApiResources(InMemoryConfig.GetApiResources())
            .AddInMemoryIdentityResources(InMemoryConfig.GetIdentityResources())
            .AddInMemoryClients(InMemoryConfig.GetClients())
            .AddTestUsers(InMemoryConfig.GetUsers().ToList());
            // .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
            //.AddProfileService<ProfileService>();

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseIdentityServer();

            // pipeline with a default route named 'default' and the following template: '{controller=Home}/{action=Index}/{id?}'.
            //app.UseMvcWithDefaultRoute();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}