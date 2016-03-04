using IdentityModel.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;

namespace IdentityServer3ForWebAPI.Controllers
{
    /// <summary>
    /// 客服端
    /// </summary>
    [RoutePrefix("api/v1/client")]
    public class ClientController : ApiController
    {
        /// <summary>
        ///获得Token
        /// </summary>
        /// <returns></returns>
        [Route("token")]
        [HttpGet]
        public async Task<IHttpActionResult> Token()
        {
            var client = new TokenClient("http://localhost:20097/connect/token",
                                         "silicon",
                                         "F621F470-9731-4A25-80EF-67A6F7C5F4B8");
            var token = client.RequestClientCredentialsAsync("api1").Result;
            if (token.IsError)
            {
                return Ok(new { IsError = true, Msg = token.HttpErrorReason, Data = string.Empty });
            }
            return Ok(new { IsError = false, Msg = string.Empty, Data = token.AccessToken });
        }
    }
}
