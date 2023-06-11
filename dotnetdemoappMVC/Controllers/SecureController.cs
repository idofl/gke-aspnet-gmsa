// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Principal;
using System.Text;
using DotNetDemoAppMvc.Models;
using System.DirectoryServices.AccountManagement;

namespace DotNetDemoAppMvc.Controllers
{
    public class SecureController : Controller
    {
        [Authorize]
        public ActionResult Authenticate()
        {
            ViewBag.Message = "Test Windows Authentication";
            var groupNames = new List<string>();
            var wi = (WindowsIdentity)User.Identity;
            var authenticationType = User.Identity.AuthenticationType;
            if (authenticationType.ToLower() == "negotiate")
            {
                var authorizationHeader = this.Request.Headers["Authorization"];
                if (authorizationHeader != null)
                {
                    var authorizationEncoded = Convert.FromBase64String(authorizationHeader.Split(' ')[1]);
                    var authorizationDecoded = Encoding.UTF8.GetString(authorizationEncoded);

                    if (authorizationDecoded.Contains("NTLM"))
                    {
                        authenticationType += " (NTLM)";
                    }
                    else
                    {
                        authenticationType += " (Kerberos)";
                    }
                }
            }

            foreach (var group in wi.Groups)
            {
                groupNames.Add(group.Translate(typeof(NTAccount)).Value);
            }

            try
            {
                var managedAdContext = new PrincipalContext(ContextType.Domain, "gmsa-test.lab","DC=gmsa-test,DC=lab");
                groupNames.Add(GetPrincipalName(managedAdContext, User.Identity.Name, "Managed AD"));

                var trustedDomainWithUserContext = new PrincipalContext(ContextType.Domain, "sub.secondary.lab", "DC=sub,DC=secondary,DC=lab", "sub\\administrator", "P@ssw0rd12!");
                groupNames.Add(GetPrincipalName(trustedDomainWithUserContext, User.Identity.Name, "Trusted using AD User"));           

                var trustedDomainContext = new PrincipalContext(ContextType.Domain, "sub.secondary.lab", "DC=sub,DC=secondary,DC=lab");
                groupNames.Add(GetPrincipalName(trustedDomainContext, User.Identity.Name, "Trusted using gMSA"));

                var impContext = wi.Impersonate();
                var trustedDomainImpersonateContext = new PrincipalContext(ContextType.Domain, "sub.secondary.lab", "DC=sub,DC=secondary,DC=lab");
                groupNames.Add(GetPrincipalName(trustedDomainImpersonateContext, User.Identity.Name, "Trusted using impersonation"));
                impContext.Undo();

            }
            catch (Exception ex)
            {
                // Silently catch to skip errors 
                groupNames.Add(ex.ToString());
            }

            return View(new SecureViewModel (){GroupNames = groupNames, AuthenticationType=authenticationType });
        }
        private string GetPrincipalName(PrincipalContext context, string userName, string contextDescription)
        {
            var userPrincipal = UserPrincipal.FindByIdentity(context, userName);

            if (userPrincipal == null)
            {
                return "Searching " + contextDescription + ": user not found";
            }
            else
            {
                return "Searching " + contextDescription + ": " + userPrincipal.DisplayName;
            }
        }
    }
}