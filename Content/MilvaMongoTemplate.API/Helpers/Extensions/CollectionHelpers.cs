using Milvasoft.Helpers.DataAccess.EfCore.Abstract.Entity;
using Milvasoft.Helpers.Extensions;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MilvaMongoTemplate.API.Helpers.Extensions;

/// <summary>
/// Helper extensions methods for Ops!yon Project.
/// </summary>
public static partial class HelperExtensions
{
    #region IEnumerable Helpers

    /// <summary>
    /// Checks guid list. If list is null or empty return default(<typeparamref name="TDTO"/>). Otherwise invoke <paramref name="returnFunc"/>.
    /// </summary>
    /// <typeparam name="TEntity"></typeparam>
    /// <typeparam name="TDTO"></typeparam>
    /// <param name="toBeCheckedList"></param>
    /// <param name="returnFunc"></param>
    /// <returns></returns>
    public static List<TDTO> CheckList<TEntity, TDTO>(this IEnumerable<TEntity> toBeCheckedList, Func<IEnumerable<TEntity>, IEnumerable<TDTO>> returnFunc)
     where TDTO : new()
     where TEntity : class, IBaseEntity<ObjectId>
     => toBeCheckedList.IsNullOrEmpty() ? new List<TDTO>() : returnFunc.Invoke(toBeCheckedList).ToList();

    /// <summary>
    /// Checks guid list. If list is null or empty return default(<typeparamref name="TDTO"/>). Otherwise invoke <paramref name="returnFunc"/>.
    /// </summary>
    /// <typeparam name="TEntity"></typeparam>
    /// <typeparam name="TDTO"></typeparam>
    /// <param name="toBeCheckedList"></param>
    /// <param name="returnFunc"></param>
    /// <returns></returns>
    public static async Task<List<TDTO>> CheckListAsync<TEntity, TDTO>(this IEnumerable<TEntity> toBeCheckedList, Func<IEnumerable<TEntity>, IEnumerable<Task<TDTO>>> returnFunc)
     where TDTO : new()
     where TEntity : class, IBaseEntity<ObjectId>
    {
        if (toBeCheckedList.IsNullOrEmpty())
            return new List<TDTO>();
        else
        {
            List<TDTO> tDTOs = new();

            var result = returnFunc.Invoke(toBeCheckedList).ToList();

            foreach (var item in result)
                tDTOs.Add(await item);

            return tDTOs;
        }
    }

    /// <summary>
    /// Checks guid object. If is null return default(<typeparamref name="TDTO"/>). Otherwise invoke <paramref name="returnFunc"/>.
    /// </summary>
    /// <typeparam name="TEntity"></typeparam>
    /// <typeparam name="TDTO"></typeparam>
    /// <param name="toBeCheckedObject"></param>
    /// <param name="returnFunc"></param>
    /// <returns></returns>
    public static TDTO CheckObject<TEntity, TDTO>(this TEntity toBeCheckedObject, Func<TEntity, TDTO> returnFunc)
      where TDTO : new()
      where TEntity : class, IBaseEntity<ObjectId>
   => toBeCheckedObject == null ? default : returnFunc.Invoke(toBeCheckedObject);

    /// <summary>
    /// Checks guid object. If is null return default(<typeparamref name="TDTO"/>). Otherwise invoke <paramref name="returnFunc"/>.
    /// </summary>
    /// <typeparam name="TEntity"></typeparam>
    /// <typeparam name="TDTO"></typeparam>
    /// <param name="toBeCheckedObject"></param>
    /// <param name="returnFunc"></param>
    /// <returns></returns>
    public static async Task<TDTO> CheckObjectAsync<TEntity, TDTO>(this TEntity toBeCheckedObject, Func<TEntity, Task<TDTO>> returnFunc)
      where TDTO : new()
      where TEntity : class, IBaseEntity<ObjectId>
    {
        if (toBeCheckedObject != null)
        {
            var result = returnFunc.Invoke(toBeCheckedObject);

            return await result;
        }
        else
            return default;
    }

    #endregion

}
