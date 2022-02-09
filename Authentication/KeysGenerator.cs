using System.Security.Cryptography;

namespace Authentication
{
    public class KeysGenerator
    {
        private const int DW_KEY_SIZE = 2048;
        
        /// <summary>
        /// Generate private/public base 64 encoded RSA keys in PKCS1 format
        /// </summary>
        /// <returns></returns>
        public static (string base64RsaPublicKey, string base64RsaPrivateKey) Generate()
        {
            var rsa = new RSACryptoServiceProvider(DW_KEY_SIZE);

            var publicKey = rsa.ExportRSAPublicKey();

            var privateKey = rsa.ExportRSAPrivateKey();

            return (Convert.ToBase64String(publicKey), Convert.ToBase64String(privateKey));
        }
    }
}