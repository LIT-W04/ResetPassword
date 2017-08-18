using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter password");
            string password = Console.ReadLine();

            bool doesMatch = PasswordHelper.PasswordMatch(password, "UoqDfLfVlB4ouw==",
                "XKsYHgKmi0Zu/buwv6pPTAB7VU3OT0vSwaHd5/IDNUs=");
            if (doesMatch)
            {
                Console.WriteLine("Right password!");
            }
            else
            {
                Console.WriteLine("BADD!!!");
            }

            Console.ReadKey(true);

        }
    }

    public static class PasswordHelper
    {
        public static string GenerateSalt()
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[10];
            provider.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        public static string HashPassword(string password, string salt)
        {
            SHA256Managed crypt = new SHA256Managed();
            string combinedString = password + salt;
            byte[] combined = Encoding.Unicode.GetBytes(combinedString);

            byte[] hash = crypt.ComputeHash(combined);
            return Convert.ToBase64String(hash);
        }

        public static bool PasswordMatch(string userInput, string salt, string passwordHash)
        {
            string userInputHash = HashPassword(userInput, salt);
            return passwordHash == userInputHash;
        }
    }
}
