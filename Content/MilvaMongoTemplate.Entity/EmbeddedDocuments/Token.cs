using Milvasoft.DataAccess.MongoDB.Entity.Abstract;

namespace MilvaMongoTemplate.Entity.EmbeddedDocuments;

/// <summary>
/// User valid tokens.
/// </summary>
public class Token : IEmbedded
{
    /// <summary>
    /// Token string.
    /// </summary>
    public string TokenString { get; set; }

    /// <summary>
    /// User mac address.
    /// </summary>
    public string MacAddress { get; set; }
}
