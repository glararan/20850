using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace _20850.Controllers
{
    [Produces("application/json")]
    [Route("api/Authorize")]
    [ApiController]
    public class AuthorizeApiController : Controller
    {
        readonly UserManager<IdentityUser> userMgr;
        readonly SignInManager<IdentityUser> signInMgr;
        readonly ILogger logger;

        public AuthorizeApiController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, ILogger<AuthorizeApiController> accountLogger)
        {
            userMgr = userManager;
            signInMgr = signInManager;
            logger = accountLogger;
        }

        [HttpGet("UserInfo")]
        public UserInfo UserInfo()
        {
            return new UserInfo
            {
                IsAuthenticated = User.Identity.IsAuthenticated,
                UserName = User.Identity.Name,
                ExposedClaims = User.Claims.ToDictionary(c => c.Type, c => c.Value),
                Cookie = HttpContext.Request.Cookies[".AspNetCore.Identity.Application"]
            };
        }

        // POST: api/Authorize/Login
        [HttpPost("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Clear the existing external cookie to ensure a clean login process
                await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                Microsoft.AspNetCore.Identity.SignInResult result = await signInMgr.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    logger.LogInformation("User logged in.");

                    return Ok();
                }

                return BadRequest(string.Join(", ", ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage)));
            }

            // If we got this far, something failed
            return BadRequest();
        }

        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                IdentityUser user = new IdentityUser { UserName = model.Email, Email = model.Email, EmailConfirmed = true };

                IdentityResult result = await userMgr.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    logger.LogInformation("User created a new account with password.");

                    await signInMgr.SignInAsync(user, isPersistent: false);

                    logger.LogInformation("User created a new account with password.");

                    return Ok();
                }

                AddErrors(result);

                return BadRequest(result.Errors.First().Description);
            }

            // If we got this far, something failed, redisplay form
            return BadRequest();
        }

        [HttpGet("Logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await signInMgr.SignOutAsync();

            logger.LogInformation("User logged out.");

            return Ok();
        }

        #region Helpers
        void AddErrors(IdentityResult result)
        {
            foreach (IdentityError error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);
        }
        #endregion
    }
}
