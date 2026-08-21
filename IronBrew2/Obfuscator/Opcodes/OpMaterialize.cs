using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator.Opcodes
{
    /// <summary>
    /// Synthetic invocation-local opcode used to replay a PC after its real
    /// instruction has been decoded into the private Flow overlay. It never
    /// represents a source instruction and is inserted only by GetInstruction.
    /// Multiple equivalent handler shapes are emitted so each prototype can
    /// select a different materializer mode without a single universal leaf.
    /// </summary>
    public sealed class OpMaterialize : VOpcode
    {
        public int Mode { get; init; }

        public override bool IsInstruction(Instruction instruction) => false;

        public override string GetObfuscated(ObfuscationContext context) => Mode switch
        {
            0 => "InstrPoint=InstrPoint-1;Flow[1]=Flow[1]-1;",
            1 => "local MaterializeTarget=InstrPoint-1;InstrPoint=MaterializeTarget;Flow[1]=MaterializeTarget;",
            2 => "Flow[1]=Flow[1]+(-1);InstrPoint=InstrPoint+(-1);",
            _ => "local MaterializeDelta=-1;Flow[1]=Flow[1]+MaterializeDelta;InstrPoint=InstrPoint+MaterializeDelta;"
        };
    }
}
