using System;

namespace IronBrew2.Obfuscator.VM_Generation
{
    /// <summary>
    /// Build-local organizations for invocation state inside the VM closure.
    /// Every template changes the number of state carriers and the access path
    /// used by opcode handlers; frame role placement and slots are randomized
    /// separately by the dedicated vm.layout stream.
    /// </summary>
    public enum VMLayout
    {
        DualPartitioned = 0,
        TieredPartitioned = 1,
        HybridLocals = 2
    }

    public static class VMLayoutSelector
    {
        public const int TemplateCount = 3;

        public static VMLayout Select(BuildRandom random)
        {
            if (random == null) throw new ArgumentNullException(nameof(random));
            return (VMLayout)random.Next(TemplateCount);
        }
    }
}
