using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace JWTAthenticationAPI.Controllers
{
    public class ApiCoreController : ApiController
    {

        [NonAction]
        protected async Task<HttpResponseMessage> CreateHttpResponseAsync(HttpRequestMessage request, Func<Task<HttpResponseMessage>> function)
        {
            HttpResponseMessage response = null;

            try
            {
                response = await function.Invoke();
            }
            catch (Exception ex)
            {
                //LogError(ex);
                response = request.CreateResponse(HttpStatusCode.InternalServerError, ex.Message);
            }

            return response;
        }

    }
}