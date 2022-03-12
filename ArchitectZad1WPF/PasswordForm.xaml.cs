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
using System.Windows.Shapes;

namespace ArchitectZad1WPF
{
    /// <summary>
    /// Логика взаимодействия для PasswordForm.xaml
    /// </summary>
    public partial class PasswordForm : Window
    {
        private PasswordForm()
        {
            InitializeComponent();
        }

        public static string ShowPasswordForm()
        {
            PasswordForm form = new PasswordForm();
            form.ShowDialog();
            return form.decPassword.Password;
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
