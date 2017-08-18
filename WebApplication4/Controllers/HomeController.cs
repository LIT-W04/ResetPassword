using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using AuthDemo.Data;
using WebApplication4.Models;

namespace WebApplication4.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Signup()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Signup(User user, string password)
        {
            var db = new UserAuthDb(Properties.Settings.Default.ConStr);
            db.AddUser(user, password);
            return Redirect("/");
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(string email, string password)
        {
            var db = new UserAuthDb(Properties.Settings.Default.ConStr);
            var user = db.Login(email, password);
            if (user == null)
            {
                return Redirect("/home/login");
            }
            FormsAuthentication.SetAuthCookie(email, true);
            return Redirect("/home/secret");
        }

        [Authorize]
        public ActionResult Secret()
        {
            bool isLoggedIn = User.Identity.IsAuthenticated;// true/false if user is logged in
            string email = User.Identity.Name; //will always match the first argument in SetAuthCookie
            var db = new UserAuthDb(Properties.Settings.Default.ConStr);
            User user = db.GetByEmail(email);
            return View(new SecretPageViewModel { User = user });
        }

        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return Redirect("/");
        }

        public ActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public ActionResult ForgotPassword(string email)
        {
            var db = new UserAuthDb(Properties.Settings.Default.ConStr);
            var userGuid = db.AddForgottenPassword(email);
            EmailSender.SendEmail(email, userGuid.User.FirstName, "Reset Password", "http://localhost:53464/home/reset?token=" + userGuid.Guid);
            return View("ForgotPasswordSent");
        }

        public ActionResult Reset(string token)
        {
            var db = new UserAuthDb(Properties.Settings.Default.ConStr);
            var forgottenPassword = db.GetForgottenPassword(token);
            if (forgottenPassword == null)
            {
                return Redirect("/");
            }

            if (forgottenPassword.Timestamp.AddMinutes(30) < DateTime.Now)
            {
                return View("Expired");
            }

            return View(new ResetViewModel { Guid = forgottenPassword.Guid });
        }

        [HttpPost]
        public ActionResult Reset(string password, string token)
        {
            var db = new UserAuthDb(Properties.Settings.Default.ConStr);
            db.ResetPassword(token, password);
            return Redirect("/home/login");
        }
    }



    public static class EmailSender
    {
        public static void SendEmail(string toEmail, string name, string subject, string link)
        {
            var fromAddress = new MailAddress("litw04emaildemo@gmail.com", "From C# App");
            var toAddress = new MailAddress(toEmail, toEmail);
            const string fromPassword = "LitW04!!";

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromAddress.Address, fromPassword)
            };
            using (var message = new MailMessage(fromAddress, toAddress)
            {
                Subject = subject,
                Body = GenerateHtml(link),
                IsBodyHtml = true
            })
            {
                smtp.Send(message);
            }
        }

        private static string GenerateHtml(string link)
        {
            string html = $"Click here to reset your password: <a href='{link}'>{link}</a>";
            return html;
        }
    }
}