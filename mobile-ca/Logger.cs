using System;
using System.Collections.Generic;

namespace mobile_ca
{
    /// <summary>
    /// Provides logging capabilities
    /// </summary>
    public static class Logger
    {
        /// <summary>
        /// Available Log types
        /// </summary>
        public enum LogType
        {
            Debug = ConsoleColor.Blue,
            Log = ConsoleColor.White,
            Info = ConsoleColor.Green,
            Warn = ConsoleColor.Yellow,
            Error = ConsoleColor.Red
        }

#if DEBUG
        /// <summary>
        /// Minimum Level required for Log output
        /// </summary>
        public static LogType MinLogLevel = LogType.Debug;
#else
        /// <summary>
        /// Minimum Level required for Log output
        /// </summary>
        public static LogType MinLogLevel = LogType.Info;
#endif
        /// <summary>
        /// Log types in order of severity Low to High
        /// </summary>
        private static readonly List<LogType> TypeOrder = new List<LogType> {
            LogType.Debug,
            LogType.Log,
            LogType.Info,
            LogType.Warn,
            LogType.Error
        };

        /// <summary>
        /// Add Cheap Multi-Threading capabilities
        /// </summary>
        private static object lockable = new object();

        /// <summary>
        /// Writes a Log Message
        /// </summary>
        /// <param name="L">Message Type</param>
        /// <param name="Message">Message</param>
        /// <param name="args">Message Arguments</param>
        private static void Write(LogType L, string Message, params object[] args)
        {
            if (TypeOrder.IndexOf(L) >= TypeOrder.IndexOf(MinLogLevel))
            {
                if (args != null && args.Length > 0)
                {
                    Message = string.Format(Message, args);
                }
                //This makes the entire thing multi-threading compatible but also somewhat slower
                lock (lockable)
                {
                    var C = Console.ForegroundColor;
                    Console.ForegroundColor = (ConsoleColor)L;
                    Console.Error.WriteLine(Message);
                    Console.ForegroundColor = C;
                }
            }
        }

        /// <summary>
        /// Logs a Debug message
        /// </summary>
        /// <param name="Message">Message</param>
        /// <param name="args">Message Arguments</param>
        public static void Debug(string Message, params object[] args)
        {
            Write(LogType.Debug, Message, args);
        }

        /// <summary>
        /// Logs an unspecified message
        /// </summary>
        /// <param name="Message">Message</param>
        /// <param name="args">Message Arguments</param>
        public static void Log(string Message, params object[] args)
        {
            Write(LogType.Log, Message, args);
        }

        /// <summary>
        /// Logs an informative message
        /// </summary>
        /// <param name="Message">Message</param>
        /// <param name="args">Message Arguments</param>
        public static void Info(string Message, params object[] args)
        {
            Write(LogType.Info, Message, args);
        }

        /// <summary>
        /// Logs a Warning message
        /// </summary>
        /// <param name="Message">Message</param>
        /// <param name="args">Message Arguments</param>
        public static void Warn(string Message, params object[] args)
        {
            Write(LogType.Warn, Message, args);
        }

        /// <summary>
        /// Logs an Error message
        /// </summary>
        /// <param name="Message">Message</param>
        /// <param name="args">Message Arguments</param>
        public static void Error(string Message, params object[] args)
        {
            Write(LogType.Error, Message, args);
            Write(LogType.Error, "Location:\r\n{0}",Environment.StackTrace);
        }

#if DEBUG
        /// <summary>
        /// Test all log types
        /// </summary>
        public static void _TEST()
        {
            foreach (var V in Enum.GetValues(typeof(LogType)))
            {
                Write((LogType)V, "Testing Logging of {0}", V);
            }
        }
#endif
    }
}
