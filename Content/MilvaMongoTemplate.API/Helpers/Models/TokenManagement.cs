using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using Milvasoft.Helpers.Identity.Abstract;
using Newtonsoft.Json;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
namespace MilvaMongoTemplate.API.Helpers.Models
{
    [JsonObject("tokenManagement")]
    public class TokenManagement : ITokenManagement
    {
        [MValidateString(1000)]
        public string Secret { get; set; }

        [MValidateString(1000)]
        public string Issuer { get; set; }

        [MValidateString(1000)]
        public string Audience { get; set; }

        [MValidateString(100)]
        public string LoginProvider { get; set; }

        [MValidateString(100)]
        public string TokenName { get; set; }

        [MValidateDecimal(100)]
        public int AccessExpiration { get; set; }

        [MValidateDecimal(100)]
        public int RefreshExpiration { get; set; }
    }
}
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
