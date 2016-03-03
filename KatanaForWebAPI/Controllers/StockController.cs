using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Flurl.Http;
using Dapper;
using Dapper.Contrib.Extensions;
using System.Data.SqlClient;
using System.Web.Configuration;

namespace KatanaForWebAPI.Controllers
{

    public class StockController : Controller
    {
        public async Task<ActionResult> Index()
        {
            var dict = new Dictionary<string, string>();
            dict.Add("得润电子", "002055");
            dict.Add("世纪星源", "000005");
            foreach (var item in dict)
            {
                string url = string.Format(@"http://q.stock.sohu.com/hisHq?code=cn_{0}&start=20160201&end=20160226&stat=1&order=D&period=d&callback=historySearchHandler&rt=jsonp", item.Value);
                var data = await url.GetStringAsync();
                var stock = JsonConvert.DeserializeObject<List<Stock>>(data.Replace(@"historySearchHandler(", "").Replace(")", ""));
                var ex = new SqlConnection();
            }

            return View();
        }
    }
    public class Stock
    {
        [JsonProperty("status")]
        public int Status;

        [JsonProperty("hq")]
        public string[][] Hq;

        [JsonProperty("code")]
        public string Code;

        [JsonProperty("stat")]
        public object[] Stat;
    }

    public class StockHq
    {
        public int Id { get; set; }
        public string Code { get; set; }
        public string Name { get; set; }
        public decimal Open { get; set; }
        public decimal Close { get; set; }
        public decimal Highest { get; set; }
        public decimal Lowest { get; set; }
        public decimal Change { get; set; }
        public decimal Chg { get; set; }
        public int Volume { get; set; }
        public decimal Turnover { get; set; }
        public decimal Rate { get; set; }
    }
}