using DirectoryServices.ProtocolsLdapServis.Models;
using System.DirectoryServices.Protocols;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Security.Principal;
using System.Net.Sockets;

namespace DirectoryServices.ProtocolsLdapServis.Service
{
    public class LdapService
    {
        public bool isServerReachable()//sunucu erişimi kontro edilir.
        {
            string ldapServer = "server.name.com";
            int ldapPort = 000;//port no
            bool isServerReachable = PingServer(ldapServer, ldapPort);
            return isServerReachable; // Exit early if the server is unreachable

        }
        private static bool PingServer(string ldapServer, int ldapPort)//ping sunucusu kontrol edilir.
        {

            using (TcpClient tcpClient = new TcpClient())
            {
                // Sunucuya belirtilen port ile bağlantı kurulmaya çalışılıyor
                try
                {
                    tcpClient.Connect(ldapServer, ldapPort);
                }
                catch (Exception ex)
                {

                    return false;
                }

                return true; // Bağlantı başarılı
            }

        }


        public bool authentication(string userName, string password, out LdapAuthenticationViewModel userProfile)
        {
            string ldapServer = "server.name.com";
            int ldapPort = 389;
            userProfile = new LdapAuthenticationViewModel();
            try
            {
                using (var connection = new LdapConnection(new LdapDirectoryIdentifier(ldapServer, ldapPort)))
                {

                    NetworkCredential networkCredential = new NetworkCredential(userName, password);// Kullanıcı kimlik bilgileri ile LDAP bağlantısını kuruyoruz
                    connection.AuthType = AuthType.Negotiate;
                    connection.Bind(networkCredential);

                    string searchFilter = $"(sAMAccountName={userName})";//arama filtresi
                    string searchBase = "DC=server,DC=name,DC=com";//base dn

                    //searchBase: Aramaya başlayacağınız temel DN(Distinguished Name).
                    //searchFilter: Aramanın uygulanacağı filtre(örneğin, kullanıcı adı sAMAccountName ile eşleşen nesneleri bulmak).
                    //searchScope: Aramanın genişliği(örneğin, Base, OneLevel, Subtree).
                    //Attributes: Aranacak nitelikler(isteğe bağlı).
                    var searchRequest = new SearchRequest(searchBase, searchFilter, SearchScope.Subtree, null);// Arama isteği oluşturuluyor


                    var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);// LDAP sunucusuna arama isteğini gönderiyoruz


                    if (searchResponse.Entries.Count > 0) // Eğer arama sonucu varsa
                    {
                        var entry = searchResponse.Entries[0];
                        userProfile.PostalAddress = GetAttributeValue(entry.Attributes, "postalAddress");
                        userProfile.Company = GetAttributeValue(entry.Attributes, "company");
                        userProfile.Department = GetAttributeValue(entry.Attributes, "department");
                        userProfile.Division = GetAttributeValue(entry.Attributes, "division");
                        userProfile.Email = GetAttributeValue(entry.Attributes, "mail");
                        userProfile.FirstName = GetAttributeValue(entry.Attributes, "givenName");
                        userProfile.Initials = GetAttributeValue(entry.Attributes, "initials");
                        userProfile.LastName = GetAttributeValue(entry.Attributes, "sn");
                        userProfile.Mobile = GetAttributeValue(entry.Attributes, "mobile");
                        userProfile.JpegPhoto = GetAttributeValue(entry.Attributes, "jpegPhoto");
                        userProfile.EmployeeType = GetAttributeValue(entry.Attributes, "employeeType");
                        userProfile.ObjectSid = GetAttributeValueGuid(entry.Attributes, "objectSid");
                        userProfile.ObjectGUID = GetAttributeValueGuid(entry.Attributes, "objectGUID");
                        userProfile.ObjectClass = GetAttributeValue(entry.Attributes, "objectClass");
                        userProfile.DistinGuishedName = entry.DistinguishedName;
                        userProfile.UserName = GetAttributeValue(entry.Attributes, "sAMAccountName");
                        userProfile.TelephoneNumber = GetAttributeValue(entry.Attributes, "telephoneNumber");
                        userProfile.userAccountControl = GetAttributeValue(entry.Attributes, "userAccountControl");
                        userProfile.userPrincipalName = GetAttributeValue(entry.Attributes, "userPrincipalName");
                    }
                }
                return true;
            }
            catch (Exception ex)
            {

                return false;
            }
        }

        private string GetAttributeValue(SearchResultAttributeCollection attributes, string attributeName)
        {
            if (attributes.Contains(attributeName))
            {
                var attributeValues = attributes[attributeName];
                if (attributeValues != null && attributeValues.Count > 0)
                {
                    return attributeValues[0].ToString(); // İlk değeri döndür
                }
            }
            return null;
        }
        private string GetAttributeValueGuid(SearchResultAttributeCollection attributes, string attributeName)
        {
            // Eğer nitelik koleksiyonu attributeName içeriyorsa
            if (attributes.Contains(attributeName))
            {
                var attributeValues = attributes[attributeName]; // Attribute'u al

                if (attributeValues != null && attributeValues.Count > 0)
                {
                    // İlk değeri alıyoruz (byte[] türünde)
                    var values = attributeValues[0] as byte[];

                    if (values != null && values.Length > 0)
                    {
                        // Eğer attributeName 'objectGUID' ise GUID formatına dönüştür
                        if (attributeName.Equals("objectGUID", StringComparison.OrdinalIgnoreCase))
                        {
                            return new Guid(values).ToString(); // Byte array'den GUID'e dönüşüm
                        }
                        // Eğer attributeName 'objectSid' ise SID formatına dönüştür
                        else if (attributeName.Equals("objectSid", StringComparison.OrdinalIgnoreCase))
                        {
                            return ConvertSidToString(values); // SID byte dizisini SID string'e dönüştür
                        }
                        else
                        {
                            // Diğer byte dizileri için
                            return BitConverter.ToString(values); // Byte dizisini string'e dönüştür
                        }
                    }
                }
            }

            return null; // Eğer attribute yoksa veya değeri boşsa null döndür
        }
        private string ConvertSidToString(byte[] sidBytes)
        {
            SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
            return sid.ToString();
        }
    }
}
