using JWTAthenticationAPI.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace JWTAthenticationAPI.Managers
{
    public class AuthenticationHandler : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                string token = GetTokenValue(request);
                
                if (TokenValid(token))
                {
                    InitializeObjects(request, token);
                }
                //else
                //{
                //    return GetUnauthorizedResponse(request);
                //}

                return base.SendAsync(request, cancellationToken);
            }
            catch
            {
                return GetUnauthorizedResponse(request);
            }
        }

        private bool TokenValid(string token)
        {
            IAuthService authService = new JWTService(new JWContainerModel().SecretKey);
            return authService.IsTokenValid(token);
        }

        // OLD
        //private void InitializeObjects(HttpRequestMessage oRequest, List<string> tokenValues)
        //{
        //    var membershipService = oRequest.GetMembershipService();
        //    var membershipCtx = membershipService.ValidateUser(tokenValues[0], tokenValues[1]);
        //    if (membershipCtx.User != null)
        //    {
        //        Ease.PPIC.BO.User.SetCurrentUser(membershipCtx.User);
        //        IPrincipal principal = membershipCtx.Principal;
        //        Thread.CurrentPrincipal = principal;
        //        HttpContext.Current.User = principal;
        //        HttpContext.Current.Items["CurrentUser"] = membershipCtx.User;
        //    }
        //    else
        //    {
        //        throw new Exception();
        //    }
        //}

        private void InitializeObjects(HttpRequestMessage oRequest, string token)
        {
            IAuthService authService = new JWTService(new JWContainerModel().SecretKey);

            List<Claim> claims = authService.GetTokenClaims(token).ToList();

            //CurrentUserViewModel vModel = JsonConvert.DeserializeObject<CurrentUserViewModel>(tokenValues[0]);

            IPrincipal principal = new GenericPrincipal(new GenericIdentity(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Name)).Value), new string[] { "Admin" });
            Thread.CurrentPrincipal = principal;
            HttpContext.Current.User = principal;
            //User oUser = MapUserFrom(vModel);
            //Ease.PPIC.BO.User.SetCurrentUser(oUser);
            //HttpContext.Current.Items["CurrentUser"] = oUser;

        }


        private string GetTokenValue(HttpRequestMessage oRequest)
        {
            string token = null;
            IEnumerable<string> authHeaderValues;
            oRequest.Headers.TryGetValues("Authorization", out authHeaderValues);
            if (authHeaderValues != null)
            {
                token = authHeaderValues.FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(token))
                {
                    token = token.Replace("Basic", "").Trim();
                }
            }
            return token;
        }


        private Task<HttpResponseMessage> GetUnauthorizedResponse(HttpRequestMessage oRequest)
        {
            var tsc = new TaskCompletionSource<HttpResponseMessage>();
            tsc.SetResult(oRequest.CreateResponse(HttpStatusCode.Unauthorized, "You are not authorized to access the system.Contact to system Administrator."));
            return tsc.Task;
        }

    }
}