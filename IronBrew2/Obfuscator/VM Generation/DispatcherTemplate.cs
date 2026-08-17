using System;

namespace IronBrew2.Obfuscator.VM_Generation
{
    /// <summary>
    /// Build-local structural forms for the opcode continuation dispatcher.
    /// These values describe genuinely different control-flow organizations,
    /// not identifier or literal substitutions.
    /// </summary>
    public enum DispatcherTemplate
    {
        LanePartitioned = 0,
        TokenThreaded = 1,
        DepthLayered = 2
    }

    public static class DispatcherTemplateSelector
    {
        public const int TemplateCount = 3;

        public static DispatcherTemplate Select(BuildRandom random)
        {
            if (random == null) throw new ArgumentNullException(nameof(random));
            return (DispatcherTemplate)random.Next(TemplateCount);
        }
    }
}
