using CryptoNotes.Classes;
using CryptoNotes.Models;
using CryptoNotes.Resources;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace CryptoNotes
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class SetupPage : ContentPage
    {
        private readonly System.Resources.ResourceManager ResMan = StringResource.ResourceManager;
        private readonly CultureInfo Culture = CultureInfo.GetCultureInfo("en");
        public SetupPage()
        {
            InitializeComponent();
            var imgsrc = ImageSource.FromStream(() => new MemoryStream(Images.notelock1));
            Logo.Source = imgsrc;
            this.Navigation.RemovePage(new MainPage());
            UnlockButton.Clicked +=  async (sender, e) =>
            {
                int pin;

                if (PIN.Text == null)
                {
                    await DisplayAlert("Alert", StringResource.NullPIN, "OK");
                    return;
                }

                if (!int.TryParse(PIN.Text, out pin))
                {
                    await DisplayAlert("Alert", StringResource.InvaildPIN, "OK");
                    return;
                }

                if (pin < 1000 || pin > 9999)
                {
                    await DisplayAlert("Alert", StringResource.InvaildPIN, "OK");
                    return;
                }

                if (Password.Text == null)
                {
                    await DisplayAlert("Alert", StringResource.NullPassword, "OK");
                    return;
                }

                PasswordLayout.IsVisible = false;
                LoadingLayout.IsVisible = true;
                Spinner.IsRunning = true;

                await Task.Run(() =>
                {
                    AppData appData = CryptoHelper.GenerateRSAPrivateKey(Enum.RSAKeySize.RSA4096, Password.Text, pin, StatusLabel, Dispatcher);
                    App.AppDatabase.SaveDataAsync(appData).Wait();

                    Dispatcher.BeginInvokeOnMainThread(async () =>
                    {
                        await Navigation.PushAsync(new MainPage());
                    });

                });
            };           
        }
    }
}