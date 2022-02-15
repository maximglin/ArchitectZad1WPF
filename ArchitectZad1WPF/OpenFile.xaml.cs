using Microsoft.Win32;
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

namespace ArchitectZad1WPF
{
    /// <summary>
    /// Логика взаимодействия для OpenFile.xaml
    /// </summary>
    public partial class OpenFile : UserControl
    {
        static OpenFile()
        {
            AbsolutePathProperty = DependencyProperty.Register(nameof(AbsolutePath), typeof(string),
                typeof(OpenFile));
        }

        public OpenFile()
        {
            InitializeComponent();
        }

        string relativepath = null;
        string absolutepath = null;

        public string RelativePath
        {
            get
            {
                return relativepath;
            }
        }
        public static readonly DependencyProperty AbsolutePathProperty;
        public string AbsolutePath
        {
            get => (string)base.GetValue(AbsolutePathProperty);
            set => base.SetValue(AbsolutePathProperty, value);
        }

        public delegate void OpenedFileHandler(object sender, string relativepath, string absolutepath);
        public event OpenedFileHandler FileOpened;

        string GetRelativePath(string filespec, string folder)
        {
            Uri pathUri = new Uri(filespec);
            // Folders must end in a slash
            if (!folder.EndsWith(System.IO.Path.DirectorySeparatorChar.ToString()))
            {
                folder += System.IO.Path.DirectorySeparatorChar;
            }
            Uri folderUri = new Uri(folder);
            return Uri.UnescapeDataString(folderUri.MakeRelativeUri(pathUri).ToString().Replace('/', System.IO.Path.DirectorySeparatorChar));
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dial = new OpenFileDialog();
            dial.Multiselect = false;

            Nullable<bool> result = dial.ShowDialog();

            if (result == true)
            {
                absolutepath = dial.FileName;
                string curdir = Environment.CurrentDirectory;
                relativepath = GetRelativePath(absolutepath, curdir);
                string fullpath = curdir + "\\" + relativepath;

                string abs2 = System.IO.Path.GetFullPath((new Uri(fullpath)).LocalPath);
                if (abs2 != absolutepath)
                    throw new Exception("INCORRENT PATH");

                if (abs)
                    txt.Text = absolutepath;
                else
                    txt.Text = relativepath;


                AbsolutePath = absolutepath;
                FileOpened?.Invoke(this, relativepath, absolutepath);
            }
        }


        bool abs = true;
        private void Mode_Click(object sender, RoutedEventArgs e)
        {
            abs = !abs;


            if (absolutepath != null && relativepath != null)
            {
                if (abs)
                    txt.Text = absolutepath;
                else
                    txt.Text = relativepath;
            }
            else
            {
                txt.Text = "";
            }
        }
    }
}
