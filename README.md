# Service to service authentication example

Code examples for service to service authentication in C#

#### Private and public keys are in PKCS1 RSA private/public key format and incoded to base 64 string

JWT header structure
```C#
public class Header
{
    [JsonPropertyName("alg")]
    public string Algorithm { get; set; } = "RSA";

    [JsonPropertyName("typ")]
    public string Type { get; set; } = "JWT";
}
```

JWT payload structure
```C#
public class Payload
{
    [JsonPropertyName("applicationId")]
    public string ApplicationId { get; set; } = string.Empty;

    [JsonPropertyName("accountId")]
    public string AccountId { get; set; } = string.Empty;
}
```

Create JWT token that will be excanched for access token
1. Convert the header JSON to base 64 string
2. Convert the payload JSON to base 64 string
3. Sign the header + (.) + payload with RSA private key and SHA1 hash algorithm
4. Create the token that consists of base64 header + (.) + base64 payload + (.) + base64 signature

```C#
public static string CreateJWTToken(Header header, Payload payload, string privateKey)
{
    var headerBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));

    var payloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));

    var signatureBase64 = Sign(privateKey, $"{headerBase64}{payloadBase64}");

    return $"{headerBase64}.{payloadBase64}.{signatureBase64}";
}

private static string Sign(string privateKey, string text)
{
    byte[] signedText;

    var privateKeyByteArray = Convert.FromBase64String(privateKey);

    using (var rsa = new RSACryptoServiceProvider())
    {
        //import the private key from PKCS1 RSA private key structure
        rsa.ImportRSAPrivateKey(privateKeyByteArray, out var _);

        //The private key is used to generate a signature that verifies that message is authentic
        signedText = rsa.SignData(Encoding.UTF8.GetBytes(text), SHA1.Create());
    }

    return Convert.ToBase64String(signedText);
}
```

Send the token to {domain}/auth/token in `Authorization: Bearer {TOKEN}` header
