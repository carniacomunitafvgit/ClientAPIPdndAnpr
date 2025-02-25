
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

try
{
    string idTokenTrack = Guid.NewGuid().ToString();
    string tokenTrackSign = GenerateToken.GetAgidTrackingSignature(
        ConfigHelper.GetConfigValue("purposeIdPdnd"),
        ConfigHelper.GetConfigValue("clientIdPdnd"),
        idTokenTrack,
        ConfigHelper.GetConfigValue("audTokenAgidJwtSignature"),
        ConfigHelper.GetConfigValue("kidPdnd"));

    byte[] hashTrack = SHA256.HashData(Encoding.UTF8.GetBytes(tokenTrackSign));
    StringBuilder hexString = new StringBuilder();
    for (int i = 0; i < hashTrack.Length; i++)
    {
        string hex = (hashTrack[i] & 0xff).ToString("x2");
        hexString.Append(hex);
    }

    string encodedTrack = hexString.ToString();


    AccessTokenPdnd p = new AccessTokenPdnd();
    string token = await p.GetRequestAccessTokenAsync(encodedTrack);

    string jsonInputString = await File.ReadAllTextAsync(ConfigHelper.GetConfigValue("fileTest"));
    byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(jsonInputString));
    string encodedBody = Convert.ToBase64String(hash);

    string tokenAgidSign = GenerateToken.GetAgidJwtSignature(encodedBody,
        ConfigHelper.GetConfigValue("clientIdPdnd"), Guid.NewGuid().ToString(), ConfigHelper.GetConfigValue("audTokenAgidJwtSignature"), ConfigHelper.GetConfigValue("kidPdnd"));

    var handler = new HttpClientHandler();
    handler.ClientCertificateOptions = ClientCertificateOption.Manual;
    handler.ServerCertificateCustomValidationCallback =
        (httpRequestMessage, cert, cetChain, policyErrors) =>
        {
            return true;
        };


    using HttpClient client = new(handler);
    client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token);
    client.DefaultRequestHeaders.Add("Agid-JWT-Signature", tokenAgidSign);
    client.DefaultRequestHeaders.Add("Agid-JWT-TrackingEvidence", tokenTrackSign);
    client.DefaultRequestHeaders.Add("Digest", "SHA-256=" + encodedBody);
    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, ConfigHelper.GetConfigValue("baseurlapi"));
    request.Content = new StringContent(jsonInputString,
                                    Encoding.UTF8,
                                    "application/json");//

    request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");


    HttpResponseMessage response = await client.SendAsync(request);
    string responseBody = await response.Content.ReadAsStringAsync();

    Console.WriteLine(response.IsSuccessStatusCode ? responseBody : "Errore: " + responseBody);
}
catch (Exception e)
{
    Console.WriteLine(e);
}
