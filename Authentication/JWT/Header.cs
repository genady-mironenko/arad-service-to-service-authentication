using System.Text.Json.Serialization;

namespace Authentication.JWT
{
    public class Header
    {
        [JsonPropertyName("alg")]
        public string Algorithm { get; set; } = "RSA";

        [JsonPropertyName("typ")]
        public string Type { get; set; } = "JWT";
    }
}
