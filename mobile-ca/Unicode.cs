using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace mobile_ca
{
    public static class Unicode
    {
        private static Dictionary<UnicodeCategory, List<char>> Categories;

        static Unicode()
        {
            Init();
        }

        private static void Init()
        {
            Categories = new Dictionary<UnicodeCategory, List<char>>();
            foreach (var Cat in Enum.GetValues(typeof(UnicodeCategory)).OfType<UnicodeCategory>())
            {
                Categories.Add(Cat, new List<char>());
            }
            for (int u = ushort.MinValue; u <= ushort.MaxValue; u++)
            {
                var c = (char)u;
                var cat = CharUnicodeInfo.GetUnicodeCategory(c);
                Categories[cat].Add(c);
            }
        }

        /// <summary>
        /// Gets all character classes and characters
        /// </summary>
        /// <remarks>This returns a copy rather than a reference</remarks>
        /// <returns>Dictionary of all character classes with characters</returns>
        public static Dictionary<UnicodeCategory, char[]> GetAll()
        {
            var Ret = new Dictionary<UnicodeCategory, char[]>();
            foreach (var Cat in Enum.GetValues(typeof(UnicodeCategory)).OfType<UnicodeCategory>())
            {
                Ret.Add(Cat, Get(Cat));
            }
            return Ret;
        }

        /// <summary>
        /// Gets a specific character class
        /// </summary>
        /// <param name="Cat">Unicode character class</param>
        /// <remarks>This returns a copy rather than a reference</remarks>
        /// <returns>Characters, null if category not found</returns>
        public static char[] Get(UnicodeCategory Cat)
        {
            if (Categories.ContainsKey(Cat))
            {
                return Categories[Cat].ToArray();
            }
            return null;
        }
    }
}
