using SQLite;
using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoNotes.Models
{
    public interface ISecureData
    {
        public int ID { get; set; }
        public string Salt { get; set; }
        public string Seed { get; set; }
        public string Data { get; set; }
        public string Iterations { get; set; }

    }

    public class BaseModel : ISecureData
    {
        [PrimaryKey, AutoIncrement]
        public int ID { get; set; }
        public string Salt { get; set; }
        public string Seed { get; set; }
        public string Data { get; set; }
        public string Iterations { get; set; }
    }
}
