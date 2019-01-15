using JWTAthenticationAPI.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceModel.Channels;
using System.Text;
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
                
                if (TokenValid(token,request))
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

        private bool TokenValid(string token, HttpRequestMessage request)
        {
            bool isValid = false;
            IAuthService authService = new JWTService(new JWContainerModel().SecretKey);

            isValid = authService.IsTokenValid(token);
            
            if (isValid)
            {
                List<Claim> claims = authService.GetTokenClaims(token).ToList();
                var ipHashed = claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.SerialNumber));
                isValid = ipHashed != null && ipHashed.Value.Trim() == GetClientIPAddressHashed(request).Trim();
            }
            return isValid;

            
        }

     
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

        public static string GetClientIPAddressHashed(HttpRequestMessage request)
        {
            string clientIPAddress = string.Empty;

            if (request == null)
            {
                return clientIPAddress;
            }

            if (request.Properties.ContainsKey("MS_HttpContext"))
            {
                clientIPAddress = ((HttpContextWrapper)request.Properties["MS_HttpContext"]).Request.UserHostAddress;
            }
            else if (request.Properties.ContainsKey(RemoteEndpointMessageProperty.Name))
            {
                RemoteEndpointMessageProperty prop = (RemoteEndpointMessageProperty)request.Properties[RemoteEndpointMessageProperty.Name];
                clientIPAddress = prop.Address;
            }
            else if (HttpContext.Current != null)
            {
                clientIPAddress = HttpContext.Current.Request.UserHostAddress;
            }

            return clientIPAddress;
            //return string.IsNullOrWhiteSpace(clientIPAddress) ? string.Empty : Sha256encrypt(clientIPAddress);
            
        }

        public static string Sha256encrypt(string phrase)
        {
            UTF8Encoding encoder = new UTF8Encoding();
            byte[] hashedDataBytes = new SHA256Managed().ComputeHash(encoder.GetBytes(phrase));
            return Convert.ToBase64String(hashedDataBytes);
        }
    }
}