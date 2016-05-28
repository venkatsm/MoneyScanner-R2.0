using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using MoneyScannerApp.Models;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace MoneyScannerApp.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View(model);
            }
        }



        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                    // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    return RedirectToAction("Index", "Home");
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }



        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            string code1 = UserManager.GenerateEmailConfirmationToken(userId);
            var result = await UserManager.ConfirmEmailAsync(userId, code1);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }





        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }




        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion


        #region Moneyscanner

        [HttpPost]
        [AllowAnonymous]
        public async Task<JsonResult> Loginuser(LoginViewModel model)
        {

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, false, shouldLockout: false);
            if (result.ToString() == "Success")
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                var confirmed = await UserManager.IsEmailConfirmedAsync(user.Id);

                if (Convert.ToBoolean(confirmed))
                {

                    return Json(result.ToString(), JsonRequestBehavior.AllowGet);
                }


            }
            return Json("Failure", JsonRequestBehavior.AllowGet);
        }

        [AllowAnonymous]
        public async Task<JsonResult> ForgotPasswordUser(ForgotPasswordViewModel model)
        {
            var user = await UserManager.FindByNameAsync(model.Email);
            string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
            var callbackUrl = string.Format("http://moneyscanner.net/resetpassword.html?key={0}&code={1}", Convert.ToString(user.Id), Convert.ToString(code));
            await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");

            return Json("Succeeded", JsonRequestBehavior.AllowGet);
        }


        [AllowAnonymous]
        public async Task<JsonResult> ResetPasswordUser(ResetPasswordUserViewModel model)
        {

            var user = await UserManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return Json("Succeeded", JsonRequestBehavior.AllowGet);
            }
            string code1 = UserManager.GeneratePasswordResetToken(model.UserId);
            var result = await UserManager.ResetPasswordAsync(model.UserId, code1, model.Password);
            if (result.Succeeded)
            {
                return Json("Succeeded", JsonRequestBehavior.AllowGet);
            }

            return Json("Failed", JsonRequestBehavior.AllowGet);
        }


        [AllowAnonymous]
        public async Task<JsonResult> RegisterUser(RegisterViewModel model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                State = model.State,
                City = model.City,
                Zipcode = model.Zipcode,
                Country = model.Country
            };
            var result = await UserManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                //await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                var callbackUrl = string.Format("http://moneyscanner.net/confirmemail.html?key={0}&code={1}", Convert.ToString(user.Id), Convert.ToString(code));
                await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");


                return Json("Succeeded", JsonRequestBehavior.AllowGet);
            }
            else
            {
                string strerror = "Falied:";
                foreach (string stre in result.Errors)
                {
                    strerror += stre;
                }

                return Json(strerror, JsonRequestBehavior.AllowGet);
            }

        }

        [AllowAnonymous]
        public async Task<JsonResult> ConfirmEmailUser(string userId, string code)
        {
            string code1 = UserManager.GenerateEmailConfirmationToken(userId);
            var result = await UserManager.ConfirmEmailAsync(userId, code1);
            if (result.Succeeded)
            { return Json("Succeeded", JsonRequestBehavior.AllowGet); }
            else
            { return Json("Failed", JsonRequestBehavior.AllowGet); }

        }


        [AllowAnonymous]
        public JsonResult GetUserDetails(string Email)
        {

            var user = UserManager.FindByEmail(Email);

            return Json(user, JsonRequestBehavior.AllowGet);


        }

        [AllowAnonymous]
        public JsonResult UpdateUserDetails(RegisterViewModel model)
        {
            var user = UserManager.FindByEmail(model.Email);

            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.State = model.State;
            user.City = model.City;
            user.Zipcode = model.Zipcode;
            user.Country = model.Country;
            user.PhoneNumber = model.Phone;

            var result = UserManager.Update(user);
            if (result.Succeeded)
            { return Json("Succeeded", JsonRequestBehavior.AllowGet); }
            else
            { return Json("Failed", JsonRequestBehavior.AllowGet); }

        }

        [AllowAnonymous]
        public async Task<JsonResult> ChangePasswordUser(ChangePasswordModel model)
        {

            var user = await UserManager.FindByEmailAsync(model.Email);

            var result = await UserManager.ChangePasswordAsync(user.Id, model.CurrentPassword, model.NewPassword);
            if (result.Succeeded)
            {
                return Json("Succeeded", JsonRequestBehavior.AllowGet);
            }

            return Json("Failed", JsonRequestBehavior.AllowGet);
        }






        [AllowAnonymous]
        public JsonResult GetFromCur()
        {
            MoneyScannerEntities mse = new MoneyScannerEntities();

            var getfromcurr = mse.TransferBases.Select(m => m.FromCurrency).Distinct();

            return Json(getfromcurr, JsonRequestBehavior.AllowGet);

        }

        [AllowAnonymous]
        public JsonResult GetToCur(string strfrom)
        {
            MoneyScannerEntities mse = new MoneyScannerEntities();

            var gettocurry = mse.TransferBases.Where(m => m.FromCurrency == strfrom).Select(m => m.ToCurrency).Distinct();

            return Json(gettocurry, JsonRequestBehavior.AllowGet);

        }

        [AllowAnonymous]
        public JsonResult gettovalue(string strfromval, string strFCurr, string strTcurr)
        {
            MoneyScannerEntities mse = new MoneyScannerEntities();

            var gettocurry = mse.TransferBases.Where(m => m.FromCurrency == strFCurr && m.ToCurrency == strTcurr).OrderByDescending(x => x.ToValue).Select(m => m.ToValue).First();

            var finalval = Convert.ToDecimal(strfromval) * gettocurry.Value;

            return Json(finalval, JsonRequestBehavior.AllowGet);
        }

        [AllowAnonymous]
        public JsonResult getfromvalue(string strtoval, string strFCurr, string strTcurr)
        {
            MoneyScannerEntities mse = new MoneyScannerEntities();

            var getfrocurry = mse.TransferBases.Where(m => m.FromCurrency == strFCurr && m.ToCurrency == strTcurr).OrderByDescending(x => x.ToValue).Select(m => m.ToValue).First();

            var finalval = Convert.ToDecimal(strtoval) / getfrocurry.Value;

            return Json(finalval, JsonRequestBehavior.AllowGet);
        }



        [AllowAnonymous]
        public JsonResult getcomparison(string strfromval, string strtoval, string strFCurr, string strTcurr, string strlist)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            List<SortList> ListAnswers = serializer.Deserialize<List<SortList>>(strlist);

            MoneyScannerEntities mse = new MoneyScannerEntities();

            var getfrocurry = mse.TransferBases.Where(m => m.FromCurrency == strFCurr && m.ToCurrency == strTcurr);
            List<CompareModel> lstcrl = new List<CompareModel>();

            foreach (var g in getfrocurry)
            {
                CompareModel cm = new CompareModel();
                cm.ImageName = g.Provider.ProviderLogo;
                cm.rating = Convert.ToString(g.Provider.ProviderRating);
                cm.todaysrate = Convert.ToString(g.ToValue);
                cm.transferfee = Convert.ToString(g.TransferFee);
                cm.transfercurrency = g.TransferCurrency;
                if (g.TransferDuration < 24)
                {
                    cm.transfertime = string.Format("{0} Hour(s)", Convert.ToString(g.TransferDuration));

                }
                else
                {

                    cm.transfertime = string.Format("{0} Day(s)", Convert.ToString(g.TransferDuration / 24));
                }
                cm.send = g.Websitelink;
                cm.amountreceived = Convert.ToString(Convert.ToDecimal(strfromval) * g.ToValue);

                lstcrl.Add(cm);


            }
            IEnumerable<CompareModel> querysorted = null;
            IOrderedEnumerable<CompareModel> lstsorted = null;
            if (ListAnswers.Count > 0)
            {
                foreach (SortList sl in ListAnswers)
                {
                    var propertyInfo = typeof(CompareModel).GetProperty(sl.strKey);

                    if (sl.strSort.ToUpper() == "ASC")
                    {
                        lstsorted = lstcrl.OrderBy(x => propertyInfo.GetValue(x, null));
                    }
                    else
                    {
                        lstsorted = lstcrl.OrderByDescending(x => propertyInfo.GetValue(x, null));
                    }
                }

            }
            else
            {
                lstsorted = lstcrl.OrderByDescending(x => x.amountreceived);
            }

            querysorted = lstsorted;

            return Json(querysorted, JsonRequestBehavior.AllowGet);
        }
        [AllowAnonymous]
        public JsonResult contactusdetails(string name, string emailid, string phoneno, string messagetext)
        {
            ContactU contactus = new ContactU();
            contactus.Name = name;
            contactus.EmailId = emailid;
            contactus.Phone = phoneno;
            contactus.Message = messagetext;

            MoneyScannerEntities mse = new MoneyScannerEntities();
            try
            {
                mse.ContactUs.Add(contactus);
                mse.SaveChanges();
                return Json("Succeeded", JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {

                return Json("Failed", JsonRequestBehavior.AllowGet);
            }


        }
        #endregion
    }
}