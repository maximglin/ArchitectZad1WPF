using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.IO;
using System.Net.Mail;
using Limilabs.Client.IMAP;
using Limilabs.Mail;
using Microsoft.Win32;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace ArchitectZad1WPF
{
    class ViewModel
    {
        public SenderViewModel SenderContext { get; } = new SenderViewModel();
        public RecipientViewModel RecipientContext { get; } = new RecipientViewModel();


        public static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);


                var certs = X509Certificate2UI.SelectFromCollection(store.Certificates, "Выбор сертификата", "", X509SelectionFlag.SingleSelection);
                //// Place all certificates in an X509Certificate2Collection object.
                //var cert = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(cert => cert.SubjectName.Name.Contains(certName));
                //

                var cert = certs.Cast<X509Certificate2>().FirstOrDefault();
                if (cert == null)
                    throw new Exception("Не выбран сертификат!");

                return cert;
            }
            finally
            {
                store.Close();
            }
        }
    }
}
