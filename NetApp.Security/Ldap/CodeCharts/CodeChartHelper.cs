namespace NetApp.Security
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Helper functions to simplify range/safe enumerations.
    /// </summary>
    internal static class CodeChartHelper
    {
        /// <summary>
        /// Generates a range of numbers starting at <paramref name="min"/>, ending at <paramref name="max"/> and using any exclusions specified in the <paramref name="exclusionFilter"/>.
        /// </summary>
        /// <param name="min">The starting number.</param>
        /// <param name="max">The finishing number.</param>
        /// <param name="exclusionFilter">A function returning true for any number to be excluded.</param>
        /// <returns>An enumerable collection of integers starting at <paramref name="min"/> and ending at <paramref name="max"/>, with any exclusions specified.</returns>
        internal static IEnumerable<int> GetRange(int min, int max, Func<int, bool> exclusionFilter)
        {
            var range = Enumerable.Range(min, (max - min + 1));
            if (exclusionFilter != null)
            {
                range = range.Where(i => !exclusionFilter(i));
            }

            return range;
        }

        /// <summary>
        /// Generates a range of numbers with no exclusions.
        /// </summary>
        /// <param name="min">The starting number.</param>
        /// <param name="max">The finishing number.</param>
        /// <returns>An enumerable collection of integers starting at <paramref name="min"/> and ending at <paramref name="max"/>.</returns>
        internal static IEnumerable<int> GetRange(int min, int max)
        {
            return GetRange(min, max, null);
        }
    }
}
