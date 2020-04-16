using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace _20850
{
    public class AuthorizeService
    {
        readonly IHttpClientFactory clientFactory;
        readonly IHttpContextAccessor contextAccessor;

        public AuthorizeService(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor)
        {
            clientFactory = httpClientFactory;
            contextAccessor = httpContextAccessor;
        }

        public async Task LoginAsync(LoginViewModel model)
        {
            HttpClient client = CreateClient();

            HttpResponseMessage result = await client.PostAsync("api/Authorize/Login", new StringContent(JsonSerializer.Serialize(model), Encoding.UTF8, "application/json"));

            if (result.StatusCode == System.Net.HttpStatusCode.BadRequest)
                throw new Exception(await result.Content.ReadAsStringAsync());

            result.EnsureSuccessStatusCode();

            string json = await client.GetStringAsync("api/Authorize/UserInfo");

            UserInfo user = Newtonsoft.Json.JsonConvert.DeserializeObject<UserInfo>(json);
        }

        public async Task LogoutAsync(string cookie)
        {
            HttpResponseMessage result = await CreateClient().GetAsync("api/Authorize/Logout");

            result.EnsureSuccessStatusCode();
        }

        public async Task RegisterAsync(RegisterViewModel model)
        {
            HttpResponseMessage result = await CreateClient().PostAsync("api/Authorize/Register", new StringContent(JsonSerializer.Serialize(model), Encoding.UTF8, "application/json"));

            if (result.StatusCode == System.Net.HttpStatusCode.BadRequest)
                throw new Exception(await result.Content.ReadAsStringAsync());
        }

        public async Task<UserInfo> GetUserInfo(string cookie)
        {
            string json = await CreateClient(cookie).GetStringAsync("api/Authorize/UserInfo");

            return Newtonsoft.Json.JsonConvert.DeserializeObject<UserInfo>(json);
        }

        HttpClient CreateClient(string cookie = null)
        {
            HttpContext context = contextAccessor.HttpContext;

            HttpClient client = clientFactory.CreateClient();
            client.BaseAddress = new Uri($"{context.Request.Scheme}://{context.Request.Host}");

            if (!string.IsNullOrEmpty(cookie))
                client.DefaultRequestHeaders.Add("Cookie", cookie);

            return client;
        }
    }
}
