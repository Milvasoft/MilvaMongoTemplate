using MongoDB.Bson;
using Newtonsoft.Json;
using System;

namespace MilvaMongoTemplate.API.Helpers;

/// <summary>
/// Provides json to objectId and reverse.
/// </summary>
public class ObjectIdJsonConverter : JsonConverter
{
    /// <summary>
    /// Determines <paramref name="objectType"/> can convertible to <see cref="ObjectId"/>.
    /// </summary>
    /// <param name="objectType"></param>
    /// <returns></returns>
    public override bool CanConvert(Type objectType) =>
        objectType == typeof(ObjectId);

    /// <summary>
    /// Reads json and parse to <see cref="ObjectId"/>.
    /// </summary>
    /// <param name="reader"></param>
    /// <param name="objectType"></param>
    /// <param name="existingValue"></param>
    /// <param name="serializer"></param>
    /// <returns></returns>
    public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        => ObjectId.Parse(reader.Value as string);

    /// <summary>
    /// Writes <see cref="ObjectId"/> to string.
    /// </summary>
    /// <param name="writer"></param>
    /// <param name="value"></param>
    /// <param name="serializer"></param>
    public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        => writer.WriteValue(((ObjectId)value).ToString());
}
