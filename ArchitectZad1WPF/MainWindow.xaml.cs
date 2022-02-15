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
                    Cryption cr = new(ecp.Text);
                    var cert = cr.MyCertificate();

                    byte[] data = File.ReadAllBytes(file.AbsolutePath);
                    var signed_data = cr.SignByCertificate(data, cert);
                    var signed_and_coded_data = cr.Base64Encode(signed_data);


                    System.IO.MemoryStream ms = new System.IO.MemoryStream();

                    ms.Write(signed_and_coded_data, 0, signed_and_coded_data.Length);
                    ms.Position = 0;

                    System.Net.Mime.ContentType ct = new System.Net.Mime.ContentType(System.Net.Mime.MediaTypeNames.Text.Plain);
                    Attachment attach = new Attachment(ms, ct);
                    attach.ContentDisposition.FileName = file.AbsolutePath.Substring(file.AbsolutePath.LastIndexOf('\\') + 1) + ".signed";



                    myMail.Attachments.Add(attach);

                    smtp.Send(myMail);

                    ms.Close();
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
                            var attachment = email.Attachments.FirstOrDefault();
                            if (attachment != null)
                            {
                                Cryption cr = new(recp.Text);
                                var cert = cr.MyCertificate();

                                var signed_and_coded_data = attachment.Data;
                                var signed_and_decoded_data = cr.RemovePkcsHeaders(signed_and_coded_data);
                                signed_and_decoded_data = cr.Base64Decode(signed_and_decoded_data);

                                var unsigned_data = cr.Unsign(signed_and_decoded_data);

                                var dialog = new SaveFileDialog();
                                dialog.FileName = attachment.FileName.Remove(attachment.FileName.LastIndexOf('.'));
                                if (dialog.ShowDialog() == true)
                                {
                                    File.WriteAllBytes(dialog.FileName, unsigned_data);
                                }
                                MessageBox.Show("Расшифровано и сохранено успешно!");
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
