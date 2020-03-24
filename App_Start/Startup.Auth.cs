using IdentityModel;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace aspnet_mvc_openid_pkce
{
    public partial class Startup
    {
        //For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Workaround Middleware for Katana Bug #197
            // Bug fix: Do not attempt to update cookies if headers have been sent.
            // https://github.com/Sustainsys/owin-cookie-saver
            app.UseKentorOwinCookieSaver();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                // uses the AuthenticationType defined by OpenIDConnect middleware.
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                ExpireTimeSpan = TimeSpan.FromMinutes(30),
                SlidingExpiration = true
            });

            // Authorization Code Flow with Proof Key for Code Exchange (PKCE)
            // https://auth0.com/docs/flows/concepts/auth-code-pkce
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "https://idp.example.com/",
                ClientId = "myclient",
                RedirectUri = "https://localhost:44361",
                CallbackPath = new PathString("/"), // *** Critical to prevent infinite loop, when running in server ***
                PostLogoutRedirectUri = "https://localhost:44361",

                // indicates idp to return authorization code. id_token is not returned, providing us the extra layer of security. 
                ResponseType = OpenIdConnectResponseType.Code,

                // indicates idp to return code in querystring
                ResponseMode = OpenIdConnectResponseMode.Query,

                Scope = "openid profile partyAPI platformAPI offline_access",

                // this value determines the value of the AuthenticationType property of the ClaimsPrincipal/ClaimsIdentity generated from the incoming token.
                // if the cookie middleware finds this in an AuthenticationResponseGrant, that’s what the cookie middleware uses to determine whether such ClaimsPrincipal/ ClaimsIdentity should be used for creating a session.
                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,

                // default is true, set it to false to decouple the session validity time from the token expires time. 
                UseTokenLifetime = false,

                // default is true, but we explicitly set it, so that when working with local idp, we can change to false.
                RequireHttpsMetadata = true,

                RedeemCode = true, // required for PKCE
                SaveTokens = true,

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = async n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                                // generate code verifier and code challenge
                                var codeVerifier = CryptoRandom.CreateUniqueId(32);

                            string codeChallenge;
                            using (var sha256 = SHA256.Create())
                            {
                                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                                codeChallenge = Base64Url.Encode(challengeBytes);
                            }

                                // set code_challenge parameter on authorization request
                                n.ProtocolMessage.SetParameter("code_challenge", codeChallenge);
                            n.ProtocolMessage.SetParameter("code_challenge_method", "S256");

                                // remember code verifier in cookie (adapted from OWIN nonce cookie)
                                n.RememberCodeVerifier(codeVerifier);
                        }

                            // if signing out, add the id_token_hint
                            if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var result = await n.OwinContext.Authentication.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);
                            var idTokenHint = result.Properties.Dictionary[OpenIdConnectParameterNames.IdToken];
                            if (idTokenHint != null)
                            {
                                n.ProtocolMessage.IdTokenHint = idTokenHint;
                            }
                        }

                        await Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = async n =>
                    {
                            // get code verifier from cookie
                            var codeVerifier = n.RetrieveCodeVerifier();

                            // attach code_verifier on token request
                            n.TokenEndpointRequest.SetParameter("code_verifier", codeVerifier);

                        await Task.FromResult(0);
                    },
                    // after authentication, inject custom agent claims to the OWIN Identity
                    SecurityTokenValidated = async n =>
                    {
                        var accessToken = n.ProtocolMessage.AccessToken;

                        // add custom claims
                        var claimsIdentify = n.AuthenticationTicket.Identity;

                        var customeClaims = new List<Claim>
                        {
                          new Claim(ClaimTypes.Role, "SystemAdmin"),
                        };

                        claimsIdentify.AddClaims(customeClaims);

                        await Task.FromResult(0);
                    }
                }
            });
        }
    }
}