using MoneyScannerApp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using System.Web.Mvc;

namespace MoneyScannerApp.Controllers
{
    public class MSServiceController : ApiController
    {
        static string host = "http://localhost:49533/";

        public Dictionary<int, string> GetMSvalues()
        {
            Dictionary<int, string> _colorMap = new Dictionary<int, string>
     {
           { 1, "blue"},
           { 2, "red" },
           { 3, "green" },
           { 4, "black" },
           { 5, "white" },
       };

            return _colorMap;
        }

        public string LoginUser(string username, string password)
        {
            ApplicationDbContext adb = new ApplicationDbContext();

            HttpClient client = new HttpClient();
            var pairs = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>( "Email", username ), 
                    new KeyValuePair<string, string>( "Password", password ), 
                    new KeyValuePair<string, string> ( "RememberMe", "false" )
                };
            var content = new FormUrlEncodedContent(pairs);

            // Attempt to get a token from the token endpoint of the Web Api host:
            HttpResponseMessage response =
                client.PostAsync(host + "Account/Loginuser", content).Result;
            var result = response.Content.ReadAsStringAsync().Result;
            return result;
            

            
        }

       
        // GET api/<controller>/5
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<controller>
        public void Post([FromBody]string value)
        {
        }

        // PUT api/<controller>/5
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/<controller>/5
        public void Delete(int id)
        {
        }
    }
}