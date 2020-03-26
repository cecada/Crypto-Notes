using SQLite;
using System;
using System.Collections.Generic;
using System.Text;
using Xamarin.Forms;

namespace CryptoNotes.Models
{
    public class AppData: BaseModel
    {
        public string RSAPrivateKey { get; set; }
        public string RSAPublicKey { get; set; }
        public string CSR { get; set; }
        //public Label label { get; set; }
        //public IDispatcher dispatcher { get; set; }
    }
}
