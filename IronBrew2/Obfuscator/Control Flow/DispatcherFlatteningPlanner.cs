using System;
using System.Collections.Generic;
using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Obfuscator.Control_Flow
{
    /// <summary>
    /// Result of the conservative, prototype-local dispatcher eligibility pass.
    /// No bytecode is changed unless the complete prototype has been validated.
    /// </summary>
    public sealed class DispatcherFlatteningDecision
    {
        internal DispatcherFlatteningDecision(bool isEligible, string reason, ControlFlowGraph graph)
        {
            IsEligible = isEligible;
            Reason = reason;
            Graph = graph;
        }

        public bool IsEligible { get; }
        public string Reason { get; }
        public ControlFlowGraph Graph { get; }
    }

    /// <summary>
    /// Selects prototypes for VM route-state dispatcher flattening. The pass is
    /// deliberately proof-oriented: malformed companion words, jump references,
    /// closure bindings or SETLIST data words cause a clean metadata-only fallback.
    /// </summary>
    public static class DispatcherFlatteningPlanner
    {
        public const int MaxBlockInstructions = 24;
        private const int MinimumInstructionCount = 6;
        private const int MaximumInstructionCount = 100000;

        public static DispatcherFlatteningDecision Analyze(Chunk chunk)
        {
            DispatcherFlatteningDecision Reject(string reason) =>
                new DispatcherFlatteningDecision(false, reason, null);

            if (chunk == null)
                return Reject("null-prototype");
            if (chunk.Instructions == null || chunk.Constants == null || chunk.Functions == null)
                return Reject("incomplete-prototype");
            if (chunk.Instructions.Count < MinimumInstructionCount)
                return Reject("too-small");
            if (chunk.Instructions.Count > MaximumInstructionCount)
                return Reject("too-large");

            try
            {
                chunk.UpdateMappings();
                var consumedData = new HashSet<int>();

                bool HasTarget(Instruction instruction, out int targetIndex)
                {
                    targetIndex = -1;
                    return instruction.RefOperands[0] is Instruction target &&
                           chunk.InstructionMap.TryGetValue(target, out targetIndex);
                }

                for (int index = 0; index < chunk.Instructions.Count; index++)
                {
                    Instruction instruction = chunk.Instructions[index];
                    if (instruction == null || instruction.Chunk != chunk)
                        return Reject("foreign-instruction");
                    if (!Enum.IsDefined(typeof(Opcode), instruction.OpCode))
                        return Reject("unsupported-opcode");

                    if (instruction.InstructionType == InstructionType.Data)
                    {
                        if (!consumedData.Contains(index))
                            return Reject("orphan-data-word");
                        continue;
                    }

                    switch (instruction.OpCode)
                    {
                        case Opcode.Jmp:
                        case Opcode.ForLoop:
                            if (!HasTarget(instruction, out _))
                                return Reject("invalid-jump-reference");
                            break;

                        case Opcode.ForPrep:
                            if (!HasTarget(instruction, out int loopIndex) ||
                                loopIndex + 1 >= chunk.Instructions.Count ||
                                chunk.Instructions[loopIndex].OpCode != Opcode.ForLoop)
                                return Reject("invalid-forprep-companion");
                            break;

                        case Opcode.Eq:
                        case Opcode.Lt:
                        case Opcode.Le:
                        case Opcode.Test:
                        case Opcode.TestSet:
                        case Opcode.TForLoop:
                            if (index + 1 >= chunk.Instructions.Count ||
                                chunk.Instructions[index + 1].OpCode != Opcode.Jmp ||
                                !HasTarget(chunk.Instructions[index + 1], out _))
                                return Reject("invalid-skip-next-companion");
                            break;

                        case Opcode.SetList when instruction.C == 0:
                            if (index + 1 >= chunk.Instructions.Count ||
                                chunk.Instructions[index + 1].InstructionType != InstructionType.Data)
                                return Reject("invalid-setlist-data-word");
                            consumedData.Add(index + 1);
                            break;

                        case Opcode.Closure:
                            if (!(instruction.RefOperands[0] is Chunk prototype) ||
                                !chunk.Functions.Contains(prototype))
                                return Reject("invalid-closure-reference");
                            if (index + prototype.UpvalueCount >= chunk.Instructions.Count)
                                return Reject("truncated-closure-bindings");
                            for (int bindingOffset = 1; bindingOffset <= prototype.UpvalueCount; bindingOffset++)
                            {
                                int bindingIndex = index + bindingOffset;
                                Opcode bindingOpcode = chunk.Instructions[bindingIndex].OpCode;
                                if (bindingOpcode != Opcode.Move && bindingOpcode != Opcode.GetUpval)
                                    return Reject("invalid-closure-binding");
                            }
                            break;
                    }
                }

                // A data word may only be consumed by its immediately preceding SETLIST.
                for (int index = 0; index < chunk.Instructions.Count; index++)
                    if (chunk.Instructions[index].InstructionType == InstructionType.Data &&
                        !consumedData.Contains(index))
                        return Reject("orphan-data-word");

                ControlFlowGraph graph = ControlFlowGraph.Build(chunk, MaxBlockInstructions);
                if (graph.EntryBlock == null || graph.Blocks.Count < 2)
                    return new DispatcherFlatteningDecision(false, "single-block", graph);

                return new DispatcherFlatteningDecision(true, "eligible", graph);
            }
            catch (Exception exception)
            {
                return Reject("analysis-failed:" + exception.GetType().Name);
            }
        }

        public static DispatcherFlatteningDecision Apply(Chunk chunk)
        {
            DispatcherFlatteningDecision decision = Analyze(chunk);
            if (chunk != null)
            {
                chunk.DispatcherFlattened = decision.IsEligible;
                chunk.DispatcherFlatteningReason = decision.Reason;
            }
            return decision;
        }
    }
}
