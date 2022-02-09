using System.Text.Json.Serialization;

namespace Authentication.JWT
{
    public class Payload
    {
        [JsonPropertyName("applicationId")]
        public string ApplicationId { get; set; } = string.Empty;

        [JsonPropertyName("accountId")]
        public string AccountId { get; set; } = string.Empty;
    }
}
