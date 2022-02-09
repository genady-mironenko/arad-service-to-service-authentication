using Authentication;
using Authentication.JWT;

const string APPLICATION_ID = "E05AB9A3538C4F7DA00C6A1EDCF7A3CB";

const string ACCOUNT_ID = "E05AB9A3538C4F7DA00C6A1EDCF7A3CB";

var (base64RsaPublicKey, base64RsaPrivateKey) = KeysGenerator.Generate();

var header = new Header
{
    Algorithm = "RSA",
    Type = "JWT"
};

var payload = new Payload
{
    ApplicationId = APPLICATION_ID,
    AccountId = ACCOUNT_ID
};

//create JWT token with the private key on the client side
var jwtTokenToSend = Token.CreateJWTToken(header, payload, base64RsaPrivateKey);

var tokenIsValid = Token.IsValid(jwtTokenToSend, base64RsaPublicKey);

Console.WriteLine($"Token in valid: {tokenIsValid}");
