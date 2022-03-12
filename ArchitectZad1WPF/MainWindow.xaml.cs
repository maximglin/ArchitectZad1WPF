using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
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
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                var cert = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(cert => cert.SubjectName.Name.Contains(certName));

                if (cert == null)
                    throw new Exception("Нет сертификата с таким именем владельца в названии!");

                return cert;
            }
            finally
            {
                store.Close();
            }
        }
        private static byte[] GetSignedHash(byte[] file, RSA privateKey)
        {
            SHA256 sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(file);

            byte[] signedHash = privateKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
           
            return signedHash;
        }


        private static bool VerifySignWithPublicKey(byte[] file, byte[] signedHash, RSA publicKey) 
        {
            SHA256 sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(file);

            return publicKey.VerifyHash(hash, signedHash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // add from,to mailaddresses
                MailAddress from = new MailAddress(login.Text);
                MailAddress to = new MailAddress(address.Text);
                MailMessage myMail = new System.Net.Mail.MailMessage(from, to);

                // add ReplyTo
                //MailAddress replyTo = new MailAddress("reply@example.com");
                //myMail.ReplyToList.Add(replyTo);

                // set subject and encoding
                myMail.Subject = theme.Text;
                myMail.SubjectEncoding = System.Text.Encoding.UTF8;

                // set body-message and encoding
                myMail.Body = text.Text;
                myMail.BodyEncoding = System.Text.Encoding.UTF8;
                // text or html
                myMail.IsBodyHtml = false;


                


                SmtpClient smtp = new(server.Text);
                smtp.UseDefaultCredentials = false;
                System.Net.NetworkCredential basicAuthenticationInfo = new
                   System.Net.NetworkCredential(login.Text, password.Password);
                smtp.Credentials = basicAuthenticationInfo;
                smtp.EnableSsl = true;


                if (File.Exists(file.AbsolutePath))
                {
                    var cert = GetCertificateFromStore(ecp.Text);

                    byte[] data = File.ReadAllBytes(file.AbsolutePath);

                    

                    var ms = new MemoryStream();

                    ms.Write(data, 0, data.Length);
                    ms.Position = 0;

                    var ct = new System.Net.Mime.ContentType(System.Net.Mime.MediaTypeNames.Text.Plain);
                    var attach = new Attachment(ms, ct);
                    attach.ContentDisposition.FileName = file.AbsolutePath.Substring(file.AbsolutePath.LastIndexOf('\\') + 1);
                    //attach.ContentDisposition.FileName = file.AbsolutePath.Substring(file.AbsolutePath.LastIndexOf('\\') + 1) + ".signed";


                    myMail.Attachments.Add(attach);


                    var ms2 = new MemoryStream();
                    byte[] encryptedHash = GetSignedHash(data, cert.GetRSAPrivateKey());
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


                




                MessageBox.Show("Успешно отправлено!");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            using (Imap imap = new Imap())
            {
                imap.ConnectSSL(rserver.Text);  // or ConnectSSL for SSL
                imap.UseBestLogin(rlogin.Text, rpassword.Password);
                imap.SelectInbox();
                List<long> uids = imap.Search(Flag.Unseen);
                foreach (long uid in uids)
                {
                    IMail email = new MailBuilder()
                        .CreateFromEml(imap.GetMessageByUID(uid));
                    

                    if(email.From.First().Address == login.Text)
                    {
                        try
                        {
                            MessageBox.Show($"Найдено письмо от {login.Text}\r\nТекст письма: {email.Text}");
                            var attachment = email.Attachments.FirstOrDefault(a => a.FileName != "sign");
                            var signAttachment = email.Attachments.FirstOrDefault(a => a.FileName == "sign");
                            if (attachment != null)
                            {
                                var cert = GetCertificateFromStore(recp.Text);

                                var checkResult = VerifySignWithPublicKey(attachment.Data, signAttachment.Data, cert.GetRSAPublicKey());

                                MessageBox.Show(checkResult?"Оригинальность файла подтверждена!":"Авторство НЕ подтверждено...");

                                var dialog = new SaveFileDialog();
                                dialog.FileName = attachment.FileName.Remove(attachment.FileName.LastIndexOf('.'));
                                if (dialog.ShowDialog() == true)
                                {
                                    File.WriteAllBytes(dialog.FileName, attachment.Data); 
                                    MessageBox.Show("Расшифровано и сохранено успешно!");
                                }
                            }
                            else
                                MessageBox.Show("Прикрепленных файлов не было...");
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(ex.Message);
                        }
                        
                        break;
                    }
                }
                imap.Close();
            }

        }
    }
}
