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
    /// 我的订单
    /// </summary>
    [RoutePrefix("api/v1/orders")]
    public class OrdersController : ApiController
    {
        /// <summary>
        /// 取消订单
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("cancel")]
        public async Task<IHttpActionResult> Cancel()
        {
            return Ok(new { IsError = false, Msg = string.Empty, Data = string.Empty });
        }
    }
}
