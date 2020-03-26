using CryptoNotes.Models;
using SQLite;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CryptoNotes.Classes
{
    public class AppDataDB
    {
        readonly SQLiteAsyncConnection _database;
        public AppDataDB(string dbPath)
        {
            _database = new SQLiteAsyncConnection(dbPath);
            _database.CreateTableAsync<AppData>();
        }
        public Task<List<AppData>> GetDataAsync()
        {
            return _database.Table<AppData>().ToListAsync();
        }

        public Task<AppData> GetDataAsync(int id = 1)
        {
            var data = _database.Table<AppData>()
                            .Where(i => i.ID == id)
                            .FirstOrDefaultAsync();
            return data;
        }

        public Task<int> SaveDataAsync(AppData note)
        {
            try
            {
                if (note == null) throw new Exception("AppData in AppDataDB:SaveDataAsync is null");
                if (note.ID != 0)
                {
                    return _database.UpdateAsync(note);
                }
                else
                {
                    return _database.InsertAsync(note);
                }
            }
            catch (Exception e)
            {
                FileHelper.WriteFile(FileHelper.ErrorPath, ErrorHelper.FormatError(e), true);
                return null;
            }
        }

        public Task<int> DeleteDataAsync(AppData note)
        {
            return _database.DeleteAsync(note);
        }
    }
}
