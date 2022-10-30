using System;
using System.Text;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net;
using System.DirectoryServices;
using System.Xml.Linq;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Collections;

namespace adaclscan
{
    class Program
    {
        static Dictionary<string, string> mapSid_DN = new Dictionary<string, string>();
        static Dictionary<string, string> mapDN_Path = new Dictionary<string, string>();
        static Dictionary<string, ActiveDirectorySecurity> mapDN_Sd = new Dictionary<string, ActiveDirectorySecurity>();
        static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("adaclscan.exe DomainController Domain username password");
                return;
            }
            String DomainController = args[0];
            String Domain = args[1];
            String username = args[2]; //域用户名
            String password = args[3]; //域用户密码  
            Simulation.Run(Domain, username, password, () =>
            {
                string myfilter = "(|";
                myfilter += "(objectclass=organizationalunit)(objectclass=user)(objectclass=person)(objectclass=computer)(objectclass=group)(objectclass=organizationalPerson)(objectClass=trustedDomain)";
                myfilter += "(objectCategory=groupPolicyContainer)(objectCategory=computer)(objectCategory=group)(objectCategory=organizationalUnit)(objectCategory=person)";
                myfilter += ")";
                DirectorySearcher searcher = Ldapcoon.getSearch(Domain, DomainController, false, false);
                SearchResultCollection result = Ldapcoon.LdapSearchAll(myfilter);
                StreamWriter sw = new StreamWriter("map_sid_dn.txt");
                foreach (SearchResult r in result)
                {
                    string sid = "";
                    string distinguishedName = "";
                    string adspath = "";
                    if (r.Properties.Contains("distinguishedName"))
                    {
                        distinguishedName = r.Properties["distinguishedName"][0].ToString();
                    }
                    if (distinguishedName == "")
                    {
                        continue;
                    }
                    if (r.Properties.Contains("objectSid"))
                    {
                        SecurityIdentifier sido = new SecurityIdentifier(r.Properties["objectSid"][0] as byte[], 0);
                        sid = sido.Value.ToString();
                        mapSid_DN[sid] = distinguishedName;
                        sw.WriteLine(sid + " " + distinguishedName);
                    }                    
                    if (r.Properties.Contains("adspath"))
                    {
                        adspath = r.Properties["adspath"][0].ToString();
                        mapDN_Path[distinguishedName] = adspath;
                    }
                    if (r.Properties.Contains("ntsecuritydescriptor"))
                    {
                        var sdbytes = (byte[])r.Properties["ntsecuritydescriptor"][0];
                        ActiveDirectorySecurity sd = new ActiveDirectorySecurity();
                        sd.SetSecurityDescriptorBinaryForm(sdbytes);
                        mapDN_Sd[distinguishedName] = sd;
                    }
                }
                sw.Close();
                //通过映射取输出
                foreach (KeyValuePair<string, ActiveDirectorySecurity> kv in mapDN_Sd)
                {
                    Console.WriteLine(kv.Key);
                    PrintAllowPermissions(kv.Value);
                    Console.WriteLine();
                }
            });

        }

        static string GetUserSidString(string sid)
        {
            if (mapSid_DN.ContainsKey(sid))
            {
                return mapSid_DN[sid].ToString();
            }
            return sid;
        }
        static void PrintAllowPermissions(ActiveDirectorySecurity sd)
        {
            var ownerSid = sd.GetOwner(typeof(SecurityIdentifier));  
            var allExtendedRightsPrincipals = new HashSet<string>();
            var fullControlPrincipals = new HashSet<string>();
            var writeOwnerPrincipals = new HashSet<string>();
            var writeDaclPrincipals = new HashSet<string>();
            var writePropertyPrincipals = new HashSet<string>();
            var genericWritePrincipals = new HashSet<string>();

            var rules = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                if ($"{rule.AccessControlType}" != "Allow")
                {
                    continue;
                }
                var sid = rule.IdentityReference.ToString();
                if (sid.Split('-').Length <= 4)
                {
                    continue;
                }
                string tempdn = GetUserSidString(sid);
                if (tempdn.StartsWith("CN=Domain Admins,CN=Users,") ||
                    tempdn.StartsWith("CN=Administrators,CN=Builtin,") ||
                    tempdn.StartsWith("CN=Enterprise Admins,CN=Users,") ||
                    tempdn.StartsWith("CN=Enterprise Key Admins,CN=Users,") ||
                    tempdn.StartsWith("CN=Key Admins,CN=Users,") ||
                    tempdn.StartsWith("CN=Exchange Servers,OU=Microsoft Exchange Security Groups,") ||
                    tempdn.StartsWith("CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,") ||
                    tempdn.StartsWith("CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,") ||
                    tempdn.StartsWith("CN=Organization Management,OU=Microsoft Exchange Security Groups,") ||
                    tempdn.StartsWith("CN=Terminal Server License Servers,CN=Builtin,") ||
                    //可以关注这2个特殊的组
                    tempdn.StartsWith("CN=Account Operators,CN=Builtin,") ||
                    tempdn.StartsWith("CN=Cert Publishers,CN=Users,")
                    )
                {
                    continue;
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                {
                    allExtendedRightsPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                {
                    fullControlPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                {
                    writeOwnerPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                {
                    writeDaclPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty)
                {
                    writePropertyPrincipals.Add(tempdn);
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                {
                    genericWritePrincipals.Add(tempdn);
                }
                /*
                Delete = 0x10000,
                ReadControl = 0x20000,
                WriteDacl = 0x40000,
                WriteOwner = 0x80000,
                Synchronize = 0x100000,
                AccessSystemSecurity = 0x1000000,
                GenericRead = 0x20094,
                GenericWrite = 0x20028,
                GenericExecute = 0x20004,
                GenericAll = 0xF01FF,
                CreateChild = 0x1,
                DeleteChild = 0x2,
                ListChildren = 0x4,
                Self = 0x8,
                ReadProperty = 0x10,
                WriteProperty = 0x20,
                DeleteTree = 0x40,
                ListObject = 0x80,
                ExtendedRight = 0x100
                 */
            }

            if (fullControlPrincipals.Count > 0)
            {
                Console.WriteLine("  GenericAll Principals    :");
                fullControlPrincipals.OrderBy(p => p).ToList().ForEach(p => {                       
                        Console.WriteLine("    " + p);
                });
            }

            if (writeOwnerPrincipals.Count > 0)
            {
                Console.WriteLine("  WriteOwner Principals    :");
                writeOwnerPrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    Console.WriteLine("    " + p);
                });
            }

            if (writeDaclPrincipals.Count > 0)
            {
                Console.WriteLine("  WriteDacl Principals     :");
                writeDaclPrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    Console.WriteLine("    " + p);
                });
            }

            if (writePropertyPrincipals.Count > 0)
            {
                Console.WriteLine("  WriteProperty Principals :");
                writePropertyPrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    Console.WriteLine("    " + p);
                });
            }

            if (writePropertyPrincipals.Count > 0)
            {
                Console.WriteLine("  GenericWrite Principals  :");
                writePropertyPrincipals.OrderBy(p => p).ToList().ForEach(p => {
                    Console.WriteLine("    " + p);
                });
            }

        }


    }
}