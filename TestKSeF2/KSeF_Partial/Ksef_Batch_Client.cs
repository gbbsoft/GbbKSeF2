using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KSeF_Batch
{
    public partial class Client
    {
        // Rozszerzenie klas wygenerowanych przez NSwag

        public System.Collections.Generic.ICollection<HeaderEntryType> HeaderEntryList;

        partial void PrepareRequest(System.Net.Http.HttpClient client, System.Net.Http.HttpRequestMessage request, System.Text.StringBuilder urlBuilder)
        {
            if (HeaderEntryList!=null)
                foreach(var itm in HeaderEntryList)
                    request.Headers.Add(itm.Key, itm.Value);
        }

        partial void ProcessResponse(System.Net.Http.HttpClient client, System.Net.Http.HttpResponseMessage response)
        {
            // poprawka błedu: status 200 zamień na 201
            if (response.RequestMessage!=null
            && response.RequestMessage.RequestUri!=null
            && response.RequestMessage.RequestUri.PathAndQuery.StartsWith("/api/batch/Init")
            && response.StatusCode == System.Net.HttpStatusCode.OK)
                response.StatusCode = System.Net.HttpStatusCode.Created;
        }

    }
}
