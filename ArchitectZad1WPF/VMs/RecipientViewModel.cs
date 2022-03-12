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
using System.Text;
using System.Windows.Input;
using System.Threading.Tasks;

namespace ArchitectZad1WPF
{
    class RecipientViewModel : BaseVM
    {
        public string SenderAddress { get; set; } = "vaspupstk@yandex.ru";
        public string PostalServer { get; set; } = "imap.yandex.ru";

        public string Login { get; set; } = "elen.glin@yandex.ru";
        public string Password { get; set; }
        public string Signer { get; set; }

        public ICommand ReceiveCommand {get;}


        public RecipientViewModel()
        {
            ReceiveCommand = new AsyncRelayCommand(async () =>
            {
                await Task.Run(ReceiveMessage);
            },
            (ex) =>
            {
                MessageBox.Show(ex.Message);
            });
        }

        private void ReceiveMessage()
        {
            using (Imap imap = new Imap())
            {
                imap.ConnectSSL(PostalServer);  // or ConnectSSL for SSL
                imap.UseBestLogin(Login, Password);
                imap.SelectInbox();
                List<long> uids = imap.Search(Flag.Unseen);
                foreach (long uid in uids)
                {
                    IMail email = new MailBuilder()
                        .CreateFromEml(imap.GetMessageByUID(uid));


                    if (email.From.First().Address == SenderAddress)
                    {
                        try
                        {
                            MessageBox.Show($"Найдено письмо от {SenderAddress}\r\nТекст письма: {email.Text}");
                            var attachment = email.Attachments.FirstOrDefault(a => a.FileName != "sign");
                            var signAttachment = email.Attachments.FirstOrDefault(a => a.FileName == "sign");
                            if (attachment != null)
                            {
                                var data = attachment.Data;
                                if(attachment.FileName.EndsWith(".enc"))
                                {
                                    var passwordPhrase = App.Current.Dispatcher.Invoke(PasswordForm.ShowPasswordForm);
                                    data = DecryptAes(data, passwordPhrase);
                                    if (data == null)
                                        throw new Exception("Неверный пароль для расшифровки!");
                                }

                                var cert = ViewModel.GetCertificateFromStore(Signer);
                                var checkResult = VerifySignWithPublicKey(data, signAttachment.Data, cert.GetRSAPublicKey());

                                MessageBox.Show(checkResult ? "Оригинальность файла подтверждена!" : "Авторство НЕ подтверждено...");

                                var dialog = new SaveFileDialog();
                                if (attachment.FileName.EndsWith(".enc"))
                                    dialog.FileName = attachment.FileName.Remove(attachment.FileName.LastIndexOf('.'));
                                else
                                    dialog.FileName = attachment.FileName;
                                if (dialog.ShowDialog() == true)
                                {
                                    File.WriteAllBytes(dialog.FileName, data);
                                    MessageBox.Show("Расшифровано и сохранено успешно!");
                                }
                            }
                            else
                                MessageBox.Show("Прикрепленных файлов не было...");
                        }
                        catch (Exception ex)
                        {
                            imap.MarkMessageUnseenByUID(uids);
                            MessageBox.Show(ex.Message);
                        }

                        break;
                    }
                }
                imap.Close();
            }
        }

        private static bool VerifySignWithPublicKey(byte[] file, byte[] signedHash, RSA publicKey)
        {
            SHA256 sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(file);

            return publicKey.VerifyHash(hash, signedHash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        private static byte[] DecryptAes(byte[] data, string password)
        {
            byte[] decrypted;
            try
            {
                using (Aes aes = Aes.Create())
                {
                    SHA256 sha = SHA256.Create();
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = sha.HashSize;
                    aes.Key = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
                    


                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        var IVlength = BitConverter.ToInt32(data, 0);
                        var IV = data.Where((b, i) => i >= 4 && i < (4+IVlength)).ToArray();

                        aes.IV = IV;
                        ICryptoTransform encryptor = aes.CreateDecryptor(aes.Key, aes.IV);


                        data = data.Where((b, i) => i >= (4 + IVlength)).ToArray();
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            csEncrypt.Write(data, 0, data.Length);
                            csEncrypt.FlushFinalBlock();

                            decrypted = msEncrypt.ToArray();
                        }
                    }
                }

                return decrypted;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
