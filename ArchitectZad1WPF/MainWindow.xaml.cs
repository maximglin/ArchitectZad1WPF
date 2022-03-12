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
        private static byte[] GetSignedHash(byte[] file, RSA rsaPrivateKey)
        {
            byte[] encryptedHash;
            using (Aes aes = Aes.Create())
            {
                // Create instance of Aes for
                // symetric encryption of the data.
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                using (ICryptoTransform transform = aes.CreateEncryptor())
                {
                    byte[] keyEncrypted = rsaPrivateKey.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);

                    // Create byte arrays to contain
                    // the length values of the key and IV.
                    byte[] LenK = new byte[4];
                    byte[] LenIV = new byte[4];

                    int lKey = keyEncrypted.Length;
                    LenK = BitConverter.GetBytes(lKey);
                    int lIV = aes.IV.Length;
                    LenIV = BitConverter.GetBytes(lIV);

                    // Write the following to the FileStream
                    // for the encrypted file (outFs):
                    // - length of the key
                    // - length of the IV
                    // - ecrypted key
                    // - the IV
                    // - the encrypted cipher content

                    SHA256 sha = SHA256.Create();
                    byte[] hash = sha.ComputeHash(file);
                    using (MemoryStream outFs = new MemoryStream())
                    {

                        outFs.Write(LenK, 0, 4);
                        outFs.Write(LenIV, 0, 4);
                        outFs.Write(keyEncrypted, 0, lKey);
                        outFs.Write(aes.IV, 0, lIV);

                        // Now write the cipher text using
                        // a CryptoStream for encrypting.
                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                        {
                            // blockSizeBytes can be any arbitrary size.
                            int blockSizeBytes = aes.BlockSize / 8;

                            outStreamEncrypted.Write(hash, 0, hash.Length);

                            outStreamEncrypted.FlushFinalBlock();
                            outStreamEncrypted.Close();
                        }
                        encryptedHash = outFs.ToArray();
                        outFs.Close();
                    }
                }
            }
            return encryptedHash;
        }


        private static bool CheckSignWithPublicKey(byte[] file, byte[] encryptedHash, RSA rsaPublicKey) 
        {
            SHA256 sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(file);
            byte[] decryptedHash;

            // Create instance of Aes for
            // symetric decryption of the data.
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;

                // Create byte arrays to get the length of
                // the encrypted key and IV.
                // These values were stored as 4 bytes each
                // at the beginning of the encrypted package.
                byte[] LenK = new byte[4];
                byte[] LenIV = new byte[4];


                // Use FileStream objects to read the encrypted
                // file (inFs) and save the decrypted file (outFs).
                using (MemoryStream inFs = new MemoryStream(encryptedHash))
                {

                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Read(LenK, 0, 3);
                    inFs.Seek(4, SeekOrigin.Begin);
                    inFs.Read(LenIV, 0, 3);

                    // Convert the lengths to integer values.
                    int lenK = BitConverter.ToInt32(LenK, 0);
                    int lenIV = BitConverter.ToInt32(LenIV, 0);

                    // Determine the start position of
                    // the cipher text (startC)
                    // and its length(lenC).
                    int startC = lenK + lenIV + 8;
                    int lenC = (int)inFs.Length - startC;

                    // Create the byte arrays for
                    // the encrypted Aes key,
                    // the IV, and the cipher text.
                    byte[] KeyEncrypted = new byte[lenK];
                    byte[] IV = new byte[lenIV];

                    // Extract the key and IV
                    // starting from index 8
                    // after the length values.
                    inFs.Seek(8, SeekOrigin.Begin);
                    inFs.Read(KeyEncrypted, 0, lenK);
                    inFs.Seek(8 + lenK, SeekOrigin.Begin);
                    inFs.Read(IV, 0, lenIV);

                    // Use RSA
                    // to decrypt the Aes key.
                    byte[] KeyDecrypted = rsaPublicKey.Decrypt(KeyEncrypted, RSAEncryptionPadding.Pkcs1);
                    

                    // Decrypt the key.
                    using (ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, IV))
                    {

                        // Decrypt the cipher text from
                        // from the FileSteam of the encrypted
                        // file (inFs) into the FileStream
                        // for the decrypted file (outFs).
                        using (MemoryStream outFs = new MemoryStream())
                        {

                            int count = 0;

                            int blockSizeBytes = aes.BlockSize / 8;
                            byte[] data = new byte[blockSizeBytes];

                            // By decrypting a chunk a time,
                            // you can save memory and
                            // accommodate large files.

                            // Start at the beginning
                            // of the cipher text.
                            inFs.Seek(startC, SeekOrigin.Begin);
                            using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                            {
                                do
                                {
                                    count = inFs.Read(data, 0, blockSizeBytes);
                                    outStreamDecrypted.Write(data, 0, count);
                                }
                                while (count > 0);

                                outStreamDecrypted.FlushFinalBlock();
                                outStreamDecrypted.Close();
                            }

                            decryptedHash = outFs.ToArray();
                            outFs.Close();
                        }
                        inFs.Close();
                    }
                }
            }

            if (decryptedHash.Length != hash.Length)
                return false;

            for(int i = 0; i < decryptedHash.Length; i++)
                if(decryptedHash[i] != hash[i])
                    return false;

            return true;
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
                    byte[] encryptedHash = GetSignedHash(data, cert.GetRSAPublicKey());
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

                                var checkResult = CheckSignWithPublicKey(attachment.Data, signAttachment.Data, cert.GetRSAPrivateKey());

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
