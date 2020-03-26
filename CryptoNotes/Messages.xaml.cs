using System;
using System.Collections.Generic;
using CryptoNotes.Classes;
using CryptoNotes.Models;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace CryptoNotes
{
    [XamlCompilation(XamlCompilationOptions.Compile)]
    public partial class Messages : ContentPage
    {
        public Messages()
        {
            InitializeComponent();
        }
        async void OnNoteAddedClicked(object sender, EventArgs e)
        {
            await Navigation.PushAsync(new CreateMessage
            {
                BindingContext = new SecureData()
            });
        }
        async void OnListViewItemSelected(object sender, SelectedItemChangedEventArgs e)
        {
            if (e.SelectedItem != null)
            {
                await Navigation.PushAsync(new CreateMessage
                {
                    BindingContext = e.SelectedItem as SecureData
                });
            }
        }
        protected override async void OnAppearing()
        {
            List<SecureData> list = new List<SecureData>();
            foreach (SecureData data in await App.NotesDatabase.GetDataAsync())
                list.Add((SecureData)CryptoHelper.AESDecrypt(data));
            NotesLists.ItemsSource = list;
            list = null;
        }
    }
}