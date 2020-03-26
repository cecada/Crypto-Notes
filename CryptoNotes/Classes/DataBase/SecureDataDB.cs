using CryptoNotes.Models;
using SQLite;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CryptoNotes.Classes
{
    public class SecureDataDB
    {
        readonly SQLiteAsyncConnection _database;
        public SecureDataDB(string dbPath)
        {
            _database = new SQLiteAsyncConnection(dbPath);
            _database.CreateTableAsync<SecureData>();
        }
        public Task<List<SecureData>> GetDataAsync()
        {
            return _database.Table<SecureData>().ToListAsync();
        }

        public Task<SecureData> GetDataAsync(int id = 0)
        {
            var data= _database.Table<SecureData>()
                            .Where(i => i.ID == id)
                            .FirstOrDefaultAsync();
            return data;
        }

        public Task<int> SaveDataAsync(SecureData note)
        {
            if (note.ID != 0)
            {
                return _database.UpdateAsync(note);
            }
            else
            {
                return _database.InsertAsync(note);
            }
        }

        public Task<int> DeleteDataAsync(SecureData note)
        {
            return _database.DeleteAsync(note);
        }
    }
}
