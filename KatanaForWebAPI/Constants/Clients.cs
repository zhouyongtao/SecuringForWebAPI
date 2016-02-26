using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace KatanaForWebAPI.Constants
{
    public static class Clients
    {
        public readonly static Client Client1 = new Client
        {
            Id = "irving",
            Secret = "123456",
            RedirectUrl = Paths.AuthorizeCodeCallBackPath
        };

        public readonly static Client Client2 = new Client
        {
            Id = "7890ab",
            Secret = "7890ab",
            RedirectUrl = Paths.ImplicitGrantCallBackPath
        };
    }

    public class Client
    {
        public string Id { get; set; }
        public string Secret { get; set; }
        public string RedirectUrl { get; set; }
    }
}