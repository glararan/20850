using Blazored.LocalStorage;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace _20850
{
    public class IdentityAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider
    {
        readonly AuthorizeService authorizeSvc;
        readonly IServiceScopeFactory scopeFactory;
        readonly IdentityOptions options;
        readonly IHttpContextAccessor httpContextAccessor;
        readonly ILocalStorageService localStorage;

        UserInfo userInfoCache;

        protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

        public IdentityAuthenticationStateProvider(AuthorizeService authorizeService, ILoggerFactory loggerFactory, IServiceScopeFactory serviceScopeFactory, IOptions<IdentityOptions> optionsAccessor, IHttpContextAccessor context, ILocalStorageService localStorageService) : base(loggerFactory)
        {
            authorizeSvc = authorizeService;
            scopeFactory = serviceScopeFactory;
            options = optionsAccessor.Value;
            httpContextAccessor = context;
            localStorage = localStorageService;
        }

        async Task<string> GetCookiesAsync()
        {
            try
            {
                string cookie = await localStorage.GetItemAsync<string>("Login");

                return $".AspNetCore.Identity.Application={cookie}";
            }
            catch (Exception ex)
            {
                return $".AspNetCore.Identity.Application={httpContextAccessor.HttpContext.Request.Cookies[".AspNetCore.Identity.Application"]}";
            }
        }

        public async Task LoginAsync(LoginViewModel model)
        {
            await authorizeSvc.LoginAsync(model);

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public async Task RegisterAsync(RegisterViewModel register)
        {
            await authorizeSvc.RegisterAsync(register);

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public async Task LogoutAsync()
        {
            await authorizeSvc.LogoutAsync(await GetCookiesAsync());

            userInfoCache = null;

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public async Task<UserInfo> GetUserInfoAsync()
        {
            if (userInfoCache != null && userInfoCache.IsAuthenticated)
                return userInfoCache;

            userInfoCache = await authorizeSvc.GetUserInfo(await GetCookiesAsync());

            return userInfoCache;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            ClaimsIdentity identity = new ClaimsIdentity();

            try
            {
                UserInfo userInfo = await GetUserInfoAsync();

                if (userInfo.IsAuthenticated)
                {
                    IEnumerable<Claim> claims = new[] { new Claim(ClaimTypes.Name, userInfoCache.UserName) }.Concat(userInfoCache.ExposedClaims.Select(c => new Claim(c.Key, c.Value)));

                    identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine("Request failed:" + ex.ToString());
            }

            return new AuthenticationState(new ClaimsPrincipal(identity));
        }

        protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState authenticationState, CancellationToken cancellationToken)
        {
            // Get the user manager from a new scope to ensure it fetches fresh data
            IServiceScope scope = scopeFactory.CreateScope();

            try
            {
                UserManager<IdentityUser> userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

                return await ValidateSecurityStampAsync(userManager, authenticationState.User);
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                    await asyncDisposable.DisposeAsync();
                else
                    scope.Dispose();
            }
        }

        async Task<bool> ValidateSecurityStampAsync(UserManager<IdentityUser> userManager, ClaimsPrincipal principal)
        {
            IdentityUser user = await userManager.GetUserAsync(principal);

            if (user is null)
                return false;
            else if (!userManager.SupportsUserSecurityStamp)
                return true;

            string principalStamp = principal.FindFirstValue(options.ClaimsIdentity.SecurityStampClaimType);
            string userStamp = await userManager.GetSecurityStampAsync(user);

            return principalStamp == userStamp;
        }
    }
}
