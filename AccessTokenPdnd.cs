using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

public class AccessTokenPdnd
{
    public async Task<string> GetRequestAccessTokenAsync(string encodedTrack)
    {
        try
        {
            string baseUrl = ConfigHelper.GetConfigValue("urltokenPdnd");
            string url = $"{baseUrl}/token.oauth2";
            string clientId = ConfigHelper.GetConfigValue("clientIdPdnd");
            string purposeId = ConfigHelper.GetConfigValue("purposeIdPdnd");
            string kid = ConfigHelper.GetConfigValue("kidPdnd");
            string aud = ConfigHelper.GetConfigValue("audPdnd");
            string idToken = "111d036d-6963-4850-aac7-1a8f1d7111";

            string jwtToken = GenerateToken.GetTokenReqAccess(encodedTrack, clientId, purposeId, idToken, kid, aud);

            var values = new Dictionary<string, string>
            {
                { "client_id", clientId },
                { "client_assertion", jwtToken },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "grant_type", "client_credentials" }
            };

            using var client = new HttpClient();
            var content = new FormUrlEncodedContent(values);
            HttpResponseMessage response = await client.PostAsync(url, content);
            string responseBody = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                using JsonDocument doc = JsonDocument.Parse(responseBody);
                return doc.RootElement.GetProperty("access_token").GetString();
            }
            else
            {
                throw new Exception(responseBody);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}
