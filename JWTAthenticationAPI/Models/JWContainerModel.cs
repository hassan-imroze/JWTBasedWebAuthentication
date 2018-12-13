using JWTAthenticationAPI.Managers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace JWTAthenticationAPI.Models
{
    public class JWContainerModel : IAuthContainerModel
    {
        
        public JWContainerModel()
        {
            SecretKey = "TW9zaGVFcmV6UHJpdmF0ZUtleQ==";
            ExpireMinutes = 1440;
            SecurityAlgorithm = SecurityAlgorithms.HmacSha256Signature;
        }

        public string SecretKey { get; set; }
        public string SecurityAlgorithm { get; set; }
        public int ExpireMinutes { get; set; }
        public Claim[] Claims { get; set; }

        public static JWContainerModel GetJWTContainerModel(string name, string email)
        {
            return new JWContainerModel()
            {
                Claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name, name),
                    new Claim(ClaimTypes.Email, email)
                }
            };
        }
    }
}