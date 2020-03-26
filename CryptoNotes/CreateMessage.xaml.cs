using CryptoNotes.Classes;
using CryptoNotes.Models;
using CryptoNotes.Resources;
using System;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace CryptoNotes
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class CreateMessage : ContentPage
    {
        public CreateMessage()
        {
            InitializeComponent();

            MessageActionSwitch.Toggled += (sender, e) =>
            {
                if (MessageActionSwitch.IsToggled)
                    RunButton.Text = "Decrypt";
                else
                    RunButton.Text = "Save";
            };

            RunButton.Clicked += (sender, e) =>
            {
                if (TextMessage.Text == null)
                {
                    DisplayAlert("Alert", StringResource.NullMessage, "OK").Wait();
                    return;
                }

                if (!MessageActionSwitch.IsToggled) Encrypt(); else Decrypt();
            };

            TextMessage.TextChanged += (sender, e) =>
            {
                if (TextMessage.Text == null || TextMessage.Text.Length == 0)
                    MessageActionSwitch.IsToggled = false;
                else if (TextMessage.Text.Contains("$CryptoApp$"))
                {
                    string[] encryptedTextArray = TextMessage.Text.Split("$CryptoApp$");
                    if (encryptedTextArray.Length > 1 && !MessageActionSwitch.IsToggled)
                        MessageActionSwitch.IsToggled = true;
                    else
                        MessageActionSwitch.IsToggled = false;
                } else
                    MessageActionSwitch.IsToggled = false;

                if (!RunButton.IsEnabled)
                {
                    RunButton.IsEnabled = true;
                    RunButton.TextColor = (Color)App.Current.Resources["InputTextColor"];
                }
            };
        }
        protected override void OnAppearing()
        {
            base.OnAppearing();
            var note = (SecureData)BindingContext;
            if (note != null)
                if (note.ID > 0)
                    Decrypt();

            RunButton.IsEnabled = false;
            RunButton.TextColor = (Color)App.Current.Resources["DisabledText"];
        }
        private void Encrypt()
        {
            if (NoteTitle.Text == null)
                NoteTitle.Text = "Untitled";

            SecureData secureData = new SecureData();
            secureData.Data = TextMessage.Text;
            secureData.ID = ((SecureData)BindingContext).ID;
            secureData.NoteTitle = NoteTitle.Text;
            secureData = (SecureData)CryptoHelper.AESEncrypt(secureData);

            if (secureData == null) return;

            App.NotesDatabase.SaveDataAsync(secureData).Wait();

            BindingContext = secureData;
        }
        private void Decrypt()
        {
            SecureData data = (SecureData)CryptoHelper.AESDecrypt(BindingContext as SecureData);
            TextMessage.Text = data.Data;
            NoteTitle.Text = data.NoteTitle;
            BindingContext = (SecureData)data;
        }
        async void OnDeleteButtonClicked(object sender, EventArgs e)
        {
            var note = (SecureData)BindingContext;
            await App.NotesDatabase.DeleteDataAsync(note);
            await Navigation.PopAsync();
        }
    }
}