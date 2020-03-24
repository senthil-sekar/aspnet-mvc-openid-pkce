using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Security.Cryptography;
using System.Text;

namespace aspnet_mvc_openid_pkce
{
    public static class OpenIdConnectMiddlewareExtension
    {
        /// <summary>
        /// Securely store the code_verifier by adding to the authentication process
        /// </summary>
        public static void RememberCodeVerifier(this RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n, string codeVerifier)
        {
            // init the type that would store state values about the authentication session
            var properties = new AuthenticationProperties();

            // secure the code_verifier value by adding to the AuthenticationProperties
            properties.Dictionary.Add("cv", codeVerifier);

            // append the code_verifier cookie to the response
            n.Options.CookieManager.AppendResponseCookie(
                n.OwinContext,
                // generate a key for the cookie
                GetCodeVerifierKey(n.ProtocolMessage.State),
                // secure the AuthenticationProperties and pass it as the cookie value
                Convert.ToBase64String(Encoding.UTF8.GetBytes(n.Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure,
                    Expires = DateTime.UtcNow + n.Options.ProtocolValidator.NonceLifetime
                });
        }

        /// <summary>
        /// Retrieve the code_verifier from authentication process
        /// </summary>
        public static string RetrieveCodeVerifier(this AuthorizationCodeReceivedNotification n)
        {
            // retreive the cookie key
            string key = GetCodeVerifierKey(n.ProtocolMessage.State);

            // retrive the cookie value by key
            string codeVerifierCookie = n.Options.CookieManager.GetRequestCookie(n.OwinContext, key);

            if (codeVerifierCookie != null)
            {
                // delete the cookie from authentication process
                var cookieOptions = new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure
                };

                n.Options.CookieManager.DeleteCookie(n.OwinContext, key, cookieOptions);
            }

            // read the AuthenticationProperties from the authentication session
            var cookieProperties = n.Options.StateDataFormat.Unprotect(Encoding.UTF8.GetString(Convert.FromBase64String(codeVerifierCookie)));

            // retrive the code_verifier value
            cookieProperties.Dictionary.TryGetValue("cv", out var codeVerifier);

            return codeVerifier;
        }

        // Generate random for cookie key
        private static string GetCodeVerifierKey(string state)
        {
            using (var hash = SHA256.Create())
            {
                return OpenIdConnectAuthenticationDefaults.CookiePrefix + "cv." + Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(state)));
            }
        }
    }
}