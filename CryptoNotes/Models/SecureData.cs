using SQLite;
using System.Text;
using CustomExtensions;
using System;

namespace CryptoNotes.Models
{
    public class SecureData : BaseModel
    {
        public string NoteTitle { get; set; }
    }
}
