using MilvaMongoTemplate.API.Helpers.Attributes.ValidationAttributes;
using Milvasoft.Helpers.Models;
using System.Collections.Generic;
using System.Linq;

namespace MilvaMongoTemplate.API.DTOs
{
    /// <summary>
    /// Paginatination params
    /// </summary>
    public class PaginationParams
    {
        /// <summary>
        /// Requested page number.
        /// </summary>
        [MValidateDecimal(0, LocalizerKey = "InvalidPageIndexMessage", FullMessage = true)]
        public int PageIndex { get; set; } = 1;

        /// <summary>
        /// Requested item count in requested page.
        /// </summary>
        [MValidateDecimal(0, LocalizerKey = "InvalidRequestedItemCountMessage", FullMessage = true)]
        public int RequestedItemCount { get; set; } = 20;

        /// <summary>
        /// Order by properties for multiple ordey by operation in same time.
        /// </summary>
        public List<OrderByProp> OrderByProps { get; set; }

        /// <summary>
        /// Sorts by ascending priority prop.
        /// </summary>
        public void SortByPriority()
        {
            OrderByProps = OrderByProps?.OrderBy(i => i.Priority)?.ToList();
        }
    }
}
