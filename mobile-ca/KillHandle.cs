using System;
using System.IO;

namespace mobile_ca
{
    /// <summary>
    /// Provides automatic file removal
    /// </summary>
    public class KillHandle : IDisposable
    {
        /// <summary>
        /// Gets the file name
        /// </summary>
        public string FileName { get; private set; }
        /// <summary>
        /// Gets if this component has been disposed
        /// </summary>
        public bool IsDisposed { get; private set; }
        /// <summary>
        /// Gets if the file was successfully deleted
        /// </summary>
        /// <remarks>This is false if not atrempted to delete yet</remarks>
        public bool FileDeleted { get; private set; }
        /// <summary>
        /// Gets the last Error message when removal fails
        /// </summary>
        /// <remarks>This is cleared if a successful removal was made. See <see cref="Delete"/></remarks>
        public Exception LastRemovalError { get; private set; }

        /// <summary>
        /// Initializes Kill Handler with a temporary file name
        /// </summary>
        public KillHandle() : this(Path.GetTempFileName())
        {

        }

        /// <summary>
        /// Initializes Kill Handler with a given file name
        /// </summary>
        /// <param name="FileName">File name</param>
        public KillHandle(string FileName)
        {
            this.FileName = Path.GetFullPath(FileName);
        }

        /// <summary>
        /// Deletes file
        /// </summary>
        ~KillHandle()
        {
            Dispose();
        }

        /// <summary>
        /// Opens file for reading
        /// </summary>
        /// <returns>File stream</returns>
        public FileStream OpenRead()
        {
            if (IsDisposed)
            {
                throw new ObjectDisposedException(nameof(KillHandle));
            }
            return File.OpenRead(FileName);
        }

        /// <summary>
        /// Opens file for writing
        /// </summary>
        /// <returns>File stream</returns>
        public FileStream OpenWrite()
        {
            if (IsDisposed)
            {
                throw new ObjectDisposedException(nameof(KillHandle));
            }
            return File.OpenWrite(FileName);
        }

        /// <summary>
        /// Writes bytes to file
        /// </summary>
        /// <param name="Data">Data</param>
        /// <remarks>File is overwritten</remarks>
        public void WriteAllBytes(byte[] Data)
        {
            File.WriteAllBytes(FileName, Data);
        }

        /// <summary>
        /// Writes a string to file
        /// </summary>
        /// <param name="Data">Data</param>
        /// <remarks>File is overwritten</remarks>
        public void WriteAllText(string Data)
        {
            File.WriteAllText(FileName, Data);
        }

        /// <summary>
        /// Writes strings to file as lines
        /// </summary>
        /// <param name="Data">Data</param>
        /// <remarks>File is overwritten</remarks>
        public void WriteAllLines(string[] Data)
        {
            File.WriteAllLines(FileName, Data);
        }

        /// <summary>
        /// Reads all bytes from the file
        /// </summary>
        /// <returns>File content</returns>
        public byte[] ReadAllBytes()
        {
            return File.ReadAllBytes(FileName);
        }

        /// <summary>
        /// Disposes the component and tries to delete the file
        /// </summary>
        public void Dispose()
        {
            lock (this)
            {
                if (!IsDisposed)
                {
                    IsDisposed = true;
                    Delete();
                }
            }
        }

        /// <summary>
        /// Attempts to delete the file
        /// </summary>
        /// <returns>true, if successfully or already deleted</returns>
        public bool Delete()
        {
            if (!FileDeleted)
            {
                Logger.Debug("Deleting {0}", FileName);
                try
                {
                    if (File.Exists(FileName))
                    {
                        File.Delete(FileName);
                    }
                    LastRemovalError = null;
                    FileDeleted = true;
                    Logger.Debug("File deleted: {0}", FileName);
                }
                catch (Exception ex)
                {
                    Logger.Warn("Unable to delete {0}. Reason: {1}", FileName, ex.Message);
                    LastRemovalError = ex;
                }
            }
            return FileDeleted;
        }
    }
}
