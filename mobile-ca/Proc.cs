using System;
using System.Runtime.InteropServices;
using System.Text;

namespace mobile_ca
{
    /// <summary>
    /// Provides information regarding the current Terminal
    /// </summary>
    public static class Proc
    {
        /// <summary>
        /// Gets the List of all processes associated with the current console
        /// </summary>
        /// <param name="processList">Placeholder array for Process IDs</param>
        /// <param name="processCount">Length of the Array</param>
        /// <returns>Number of processes associated with this terminal</returns>
        /// <remarks>If the return value is bigger than <paramref name="processCount"/> you need to extend the array as no entries were added in that case</remarks>
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetConsoleProcessList(uint[] processList, int processCount);

        /// <summary>
        /// Gets the list of all process IDs associated with this terminal
        /// </summary>
        /// <returns>Process ID list</returns>
        public static uint[] GetConsoleProcList()
        {
            uint[] List = new uint[100];
            int Count = int.MaxValue;
            while (Count > List.Length)
            {
                Count = GetConsoleProcessList(List, List.Length);
                if (Count > List.Length)
                {
                    //Add some extra space in case processes were spawned.
                    //No need to use Array.Resize since the contents are not set at all if the list is too small
                    List = new uint[Count + 10];
                }
            }
            Array.Resize(ref List, Count);
            return List;
        }

        /// <summary>
        /// Gets the number of processes associated with this terminal
        /// </summary>
        /// <returns>Number of processes including this one</returns>
        /// <remarks>This call is faster than <see cref="GetConsoleProcList"/>().Length</remarks>
        public static int GetConsoleProcCount()
        {
            return GetConsoleProcessList(new uint[1], 1);
        }
    }
}
