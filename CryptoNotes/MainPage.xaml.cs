using System.ComponentModel;
using CryptoNotes.Resources;
using System.IO;
using CryptoNotes.Classes;
using Xamarin.Forms;
using Xamarin.Essentials;

namespace CryptoNotes
{
    [DesignTimeVisible(false)]
    public partial class MainPage : ContentPage
    {
        public MainPage()
        {
            InitializeComponent();
            var imgsrc = ImageSource.FromStream(() => new MemoryStream(Images.notelock1));
            Logo.Source = imgsrc;
            
            App.SecureApp();

            SetupButton.Clicked += async (sender, e) =>
            {
                await Navigation.PushAsync(new SetupPage());
            };

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
                    await DisplayAlert("Alert", StringResource.NullPIN, "OK");
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

                if (CryptoHelper.LoadRSAKey(Password.Text,pin))
                {
                    await SecureStorage.SetAsync("PIN", CryptoHelper.RSAEncrypt(PIN.Text)).ConfigureAwait(false);
                    await Navigation.PushAsync(new Messages());
                }
                else
                {
                    await DisplayAlert("Alert", StringResource.InvalidLogin, "OK");
                    return;
                }
            };
            CheckUI();
        }
        private void CheckUI()
        {
            Dispatcher.BeginInvokeOnMainThread(() =>
            {
                if (CryptoHelper.DoesRSAKeyExists())
                {
                    PasswordLayout.IsVisible = true;
                    PIN.IsVisible = true;
                    Password.IsVisible = true;
                    NewAccountLayout.IsVisible = false;
                }
                else
                {
                    PasswordLayout.IsVisible = false;
                    PIN.IsVisible = false;
                    Password.IsVisible = false;
                    NewAccountLayout.IsVisible = true;
                }
            });
        }
        protected override void OnAppearing()
        {
            base.OnAppearing();
            CheckUI();
        }
    }
}
