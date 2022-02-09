using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Authentication.JWT
{
    public class Token
    {
        /// <summary>
        /// Create JWT token on the client side
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Basic representation of the token parting and signature validation
        /// </summary>
        /// <param name="jwtTokenToValidate"></param>
        /// <param name="base64RsaPublicKey"></param>
        /// <returns></returns>
        public static bool IsValid(string jwtTokenToValidate, string base64RsaPublicKey)
        {
            var textSpliten = jwtTokenToValidate.Split('.');

            var header = textSpliten[0];

            var payload = textSpliten[1];

            var plainText = $"{header}{payload}";

            var plainTextToValidate = Encoding.UTF8.GetBytes(plainText);

            var signature = Convert.FromBase64String(textSpliten[2]);

            var rsaRead = new RSACryptoServiceProvider();

            //import the private key from PKCS1 RSA public key structure
            rsaRead.ImportRSAPublicKey(Convert.FromBase64String(base64RsaPublicKey), out var _);

            if (rsaRead.VerifyData(plainTextToValidate,
                                   SHA1.Create(),
                                   signature))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
