using CryptoNotes.Classes;
using CryptoNotes.Enum;
using System;
using System.IO;
using Xamarin.Essentials;
using Xamarin.Forms;

namespace CryptoNotes
{
    public partial class App : Application
    {
        static SecureDataDB notesdatabase;
        static AppDataDB appdatabase;

        public static SecureDataDB NotesDatabase
        {
            get
            {
                if (notesdatabase == null)
                {
                    notesdatabase = new SecureDataDB(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Notes.db3"));
                }
                return notesdatabase;
            }
        }

        public static AppDataDB AppDatabase
        {
            get
            {
                if (appdatabase == null)
                {
                    appdatabase = new AppDataDB(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "App.db3"));
                }
                return appdatabase;
            }
        }

        public App()
        {
            InitializeComponent();
            
            SecureApp();
            FileHelper.DeleteFile(FileHelper.ErrorPath);

            MainPage = new NavigationPage(new MainPage());
            ((NavigationPage)MainPage).BarBackgroundColor = (Color)Application.Current.Resources["NavigationBackgroundColor"];
            ((NavigationPage)MainPage).BarTextColor = (Color)Application.Current.Resources["AccentColor"];

        }
        static public void SecureApp()
        {
            SecureStorage.Remove(KeyType.PrivateKey.ToString());
            SecureStorage.Remove("PIN");
        }
        protected override void OnSleep()
        {
            SecureApp();
        }

        protected override void OnResume()
        {
            SecureApp();
        }
    }
}
