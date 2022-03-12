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
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            this.DataContext = new ViewModel();
        }


        private void password_PasswordChanged(object sender, RoutedEventArgs e)
        {
            (this.DataContext as ViewModel).SenderContext.Password = password.Password;
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            (this.DataContext as ViewModel).SenderContext.EncryprionPasswordPhrase = encPassword.Password;
        }

        private void rpassword_PasswordChanged(object sender, RoutedEventArgs e)
        {
            (this.DataContext as ViewModel).RecipientContext.Password = rpassword.Password;
        }
    }
}
