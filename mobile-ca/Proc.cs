using System;
using System.Runtime.InteropServices;
using System.Text;

namespace mobile_ca
{
    public static class Proc
    {
        [DllImport("kernel32.dll", ExactSpelling = true, EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetConsoleProcessList(uint[] processList, int processCount);

        public static uint[] GetConsoleProcList()
        {
            uint[] List = new uint[100];
            int Count = int.MaxValue;
            while (Count > List.Length)
            {
                Count = GetConsoleProcessList(List, List.Length);
                if (Count > List.Length)
                {
                    List = new uint[Count + 10];
                }
            }
            Array.Resize(ref List, Count);
            return List;
        }

        public static int GetConsoleProcCount()
        {
            return GetConsoleProcList().Length;
        }
    }
}
