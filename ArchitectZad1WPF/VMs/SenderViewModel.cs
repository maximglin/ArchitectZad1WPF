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
using System.Windows.Input;
using System.Threading.Tasks;
using System.Text;

namespace ArchitectZad1WPF
{
    class SenderViewModel : BaseVM
    {
        public string PostalServer { get; set; } = "smtp.yandex.ru";

        public string Login { get; set; } = "vaspupstk@yandex.ru";
        public string Password { get; set; }
        public string RecipientAddress { get; set; } = "elen.glin@yandex.ru";
        public string Subject { get; set; } = "Тестовое письмо";
        public string MailText { get; set; } = string.Empty;
        public string AttachedFilePath { get; set; }
        public string Signer { get; set; }


        public bool EncryptionEnabled { get; set; } = false;
        public string EncryprionPasswordPhrase { get; set; } = string.Empty;


        public ICommand SendCommand { get; }


        public SenderViewModel()
        {
            SendCommand = new AsyncRelayCommand(async () =>
            {
                await Task.Run(SendMessage);
                MessageBox.Show("Отправлено");
            }, 
            (ex) =>
            {
                MessageBox.Show(ex.Message);
            });
        }

        private static byte[] GetSignedHash(byte[] file, RSA privateKey)
        {
            SHA256 sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(file);

            byte[] signedHash = privateKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return signedHash;
        }

        private void SendMessage()
        {
            var from = new MailAddress(Login);
            var to = new MailAddress(RecipientAddress);
            var myMail = new System.Net.Mail.MailMessage(from, to);

            myMail.Subject = Subject;
            myMail.SubjectEncoding = System.Text.Encoding.UTF8;
            myMail.Body = MailText;
            myMail.BodyEncoding = System.Text.Encoding.UTF8;
            myMail.IsBodyHtml = false;


            SmtpClient smtp = new(PostalServer);
            smtp.UseDefaultCredentials = false;
            System.Net.NetworkCredential basicAuthenticationInfo = new
               System.Net.NetworkCredential(Login, Password);
            smtp.Credentials = basicAuthenticationInfo;
            smtp.EnableSsl = true;


            if (File.Exists(AttachedFilePath))
            {
                var cert = ViewModel.GetCertificateFromStore(Signer);
                var data = File.ReadAllBytes(AttachedFilePath);
                var encryptedHash = GetSignedHash(data, cert.GetRSAPrivateKey());

                if (EncryptionEnabled)
                    data = EncryptAes(data, EncryprionPasswordPhrase);


                using var ms = new MemoryStream();
                using var ms2 = new MemoryStream();
                ms.Write(data, 0, data.Length);
                ms.Position = 0;
                var ct = new System.Net.Mime.ContentType(System.Net.Mime.MediaTypeNames.Text.Plain);
                var attach = new Attachment(ms, ct);
                attach.ContentDisposition.FileName = AttachedFilePath.Substring(AttachedFilePath.LastIndexOf('\\') + 1);
                if (EncryptionEnabled)
                    attach.ContentDisposition.FileName += ".enc";



                myMail.Attachments.Add(attach);


                ms2.Write(encryptedHash, 0, encryptedHash.Length);
                ms2.Position = 0;
                var ct2 = new System.Net.Mime.ContentType(System.Net.Mime.MediaTypeNames.Text.Plain);
                var attach2 = new Attachment(ms2, ct2);
                attach2.ContentDisposition.FileName = "sign";

                myMail.Attachments.Add(attach2);

                smtp.Send(myMail);

                ms.Close();
                ms2.Close();
            }
            else
                smtp.Send(myMail);
                //await smtp.SendMailAsync(myMail);
        }


        static byte[] EncryptAes(byte[] data, string password)
        {
            byte[] encrypted;


            using (Aes aes = Aes.Create())
            {
                SHA256 sha = SHA256.Create();
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = sha.HashSize;
                aes.GenerateIV();
                aes.Key = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
                


                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    var IVlength = BitConverter.GetBytes(aes.IV.Length);
                    msEncrypt.Write(IVlength, 0, IVlength.Length);
                    msEncrypt.Write(aes.IV, 0, aes.IV.Length);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(data, 0, data.Length);
                        csEncrypt.FlushFinalBlock();

                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }
    }
}
