using JWTAthenticationAPI.Managers;
using JWTAthenticationAPI.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;

namespace JWTAthenticationAPI.Controllers
{
    [RoutePrefix("api/account")]
    public class AccountController : ApiCoreController
    {
        [HttpGet]
        [Route("Login")]
        public async Task<HttpResponseMessage> Login(string UserID,string Password)
        {
            return await CreateHttpResponseAsync(Request,async () =>
            {
                string token = string.Empty;
                if (UserID == "Hassan" && Password == "x")
                {
                    var model = await Task.Run(() => JWContainerModel.GetJWTContainerModel(UserID, "hassan@gmail.com"));
                    IAuthService authService = new JWTService(model.SecretKey);
                    token = authService.GenerateToken(model);
                }
                else
                {
                    throw new Exception("UserID/Password not valid");
                }
                return Request.CreateResponse(HttpStatusCode.OK,token);

            });
        }

        [HttpGet]
        [Authorize]
        [Route("SecuredResource")]
        public async Task<HttpResponseMessage> Get()
        {
            return await CreateHttpResponseAsync(Request, async () =>
            {
                return Request.CreateResponse(HttpStatusCode.OK, "This is secured");
            });
        }
    }
}
