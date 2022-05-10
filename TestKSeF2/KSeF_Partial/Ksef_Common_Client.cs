using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KSeF_Common
{
    public partial class Client
    {
        // Rozszerzenie klas wygenerowanych przez NSwag

        //public string OurSessionToken { get; set; }

        //partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, System.Text.StringBuilder urlBuilder)
        //{
        //    if (OurSessionToken != null)
        //        request.Headers.Add("SessionToken", OurSessionToken);
        //}

        partial void UpdateJsonSerializerSettings(Newtonsoft.Json.JsonSerializerSettings settings)
        {
            settings.NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore;
            
        }
    }
}
