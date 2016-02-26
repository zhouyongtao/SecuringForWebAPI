using KatanaForWebAPI.Constants;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace KatanaForWebAPI.Controllers
{
    public class OAuthController : Controller
    {
        /// <summary>
        /// 授权码模式授权
        /// </summary>
        /// <returns></returns>
        public ActionResult Authorize()
        {
            var authentication = HttpContext.GetOwinContext().Authentication;
            var ticket = authentication.AuthenticateAsync(Paths.AuthenticationType).Result;
            var identity = ticket != null ? ticket.Identity : null;
            if (identity == null)
            {
                authentication.Challenge(Paths.AuthenticationType);
                return new HttpUnauthorizedResult();
            }
            var scopes = (Request.QueryString.Get("scope") ?? "").Split(' ');
            if (Request.HttpMethod == "POST")
            {
                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Grant")))
                {
                    identity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);
                    foreach (var scope in scopes)
                    {
                        identity.AddClaim(new Claim("urn:oauth:scope", scope));
                    }
                    authentication.SignIn(identity);
                }
                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Login")))
                {
                    authentication.SignOut("Application");
                    authentication.Challenge("Application");
                    return new HttpUnauthorizedResult();
                }
            }
            return View();
        }
    }
}