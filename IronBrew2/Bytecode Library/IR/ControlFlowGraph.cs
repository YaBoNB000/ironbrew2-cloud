using System;
using System.Collections.Generic;
using System.Linq;
using IronBrew2.Bytecode_Library.Bytecode;

namespace IronBrew2.Bytecode_Library.IR
{
    /// <summary>
    /// Stable, instruction-indexed basic block used by the protected wire format.
    /// Successor and predecessor sets describe the Lua 5.1 execution paths after
    /// accounting for skip-next instructions and their companion JMP words.
    /// </summary>
    public sealed class ControlFlowBlock
    {
        internal ControlFlowBlock(int id, int start, int endExclusive)
        {
            Id = id;
            Start = start;
            EndExclusive = endExclusive;
        }

        public int Id { get; }
        public int Start { get; }
        public int EndExclusive { get; }
        public int Count => EndExclusive - Start;
        public List<ControlFlowBlock> Successors { get; } = new List<ControlFlowBlock>();
        public List<ControlFlowBlock> Predecessors { get; } = new List<ControlFlowBlock>();
    }

    /// <summary>
    /// Explicit CFG for one prototype. The graph is built before opcode mutation,
    /// while instruction references still describe the original Lua bytecode.
    /// Long straight-line regions are subdivided without merging real CFG edges.
    /// </summary>
    public sealed class ControlFlowGraph
    {
        private ControlFlowGraph(List<ControlFlowBlock> blocks)
        {
            Blocks = blocks;
            EntryBlock = blocks.Count == 0 ? null : blocks[0];
        }

        public IReadOnlyList<ControlFlowBlock> Blocks { get; }
        public ControlFlowBlock EntryBlock { get; }

        public static ControlFlowGraph Build(Chunk chunk, int maxBlockInstructions)
        {
            if (chunk == null)
                throw new ArgumentNullException(nameof(chunk));
            if (maxBlockInstructions <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxBlockInstructions));

            int instructionCount = chunk.Instructions.Count;
            if (instructionCount == 0)
                return new ControlFlowGraph(new List<ControlFlowBlock>());

            chunk.UpdateMappings();
            var successors = new List<int>[instructionCount];
            var leaders = new HashSet<int> { 0 };

            for (int index = 0; index < instructionCount; index++)
            {
                successors[index] = GetInstructionSuccessors(chunk, index);
                bool onlyFallthrough = successors[index].Count == 1 && successors[index][0] == index + 1;
                if (!onlyFallthrough && index + 1 < instructionCount)
                    leaders.Add(index + 1);

                foreach (int target in successors[index])
                {
                    if (target >= 0 && target < instructionCount && target != index + 1)
                        leaders.Add(target);
                }
            }

            int[] naturalLeaders = leaders.OrderBy(value => value).ToArray();
            for (int leaderIndex = 0; leaderIndex < naturalLeaders.Length; leaderIndex++)
            {
                int start = naturalLeaders[leaderIndex];
                int end = leaderIndex + 1 < naturalLeaders.Length
                    ? naturalLeaders[leaderIndex + 1]
                    : instructionCount;
                for (int split = start + maxBlockInstructions; split < end; split += maxBlockInstructions)
                    leaders.Add(split);
            }

            int[] ordered = leaders
                .Where(value => value >= 0 && value < instructionCount)
                .OrderBy(value => value)
                .ToArray();
            var blocks = new List<ControlFlowBlock>(ordered.Length);
            var instructionToBlock = new ControlFlowBlock[instructionCount];

            for (int index = 0; index < ordered.Length; index++)
            {
                int start = ordered[index];
                int end = index + 1 < ordered.Length ? ordered[index + 1] : instructionCount;
                if (end <= start)
                    continue;

                var block = new ControlFlowBlock(blocks.Count, start, end);
                blocks.Add(block);
                for (int instructionIndex = start; instructionIndex < end; instructionIndex++)
                    instructionToBlock[instructionIndex] = block;
            }

            foreach (ControlFlowBlock block in blocks)
            {
                foreach (int targetIndex in successors[block.EndExclusive - 1])
                {
                    if (targetIndex < 0 || targetIndex >= instructionCount)
                        continue;
                    ControlFlowBlock target = instructionToBlock[targetIndex];
                    if (target == null || block.Successors.Contains(target))
                        continue;
                    block.Successors.Add(target);
                    target.Predecessors.Add(block);
                }
            }

            return new ControlFlowGraph(blocks);
        }

        private static List<int> GetInstructionSuccessors(Chunk chunk, int index)
        {
            int count = chunk.Instructions.Count;
            Instruction instruction = chunk.Instructions[index];
            var result = new List<int>(2);

            void Add(int target)
            {
                if (target >= 0 && target < count && !result.Contains(target))
                    result.Add(target);
            }

            int ReferencedTarget(Instruction source)
            {
                if (source.RefOperands[0] is Instruction target &&
                    chunk.InstructionMap.TryGetValue(target, out int targetIndex))
                    return targetIndex;
                return -1;
            }

            int CompanionJumpTarget()
            {
                if (index + 1 >= count)
                    return -1;
                Instruction companion = chunk.Instructions[index + 1];
                return companion.OpCode == Opcode.Jmp ? ReferencedTarget(companion) : -1;
            }

            if (instruction.InstructionType == InstructionType.Data)
                return result;

            switch (instruction.OpCode)
            {
                case Opcode.Return:
                case Opcode.TailCall:
                    break;

                case Opcode.Jmp:
                    Add(ReferencedTarget(instruction));
                    break;

                case Opcode.ForLoop:
                    Add(ReferencedTarget(instruction));
                    Add(index + 1);
                    break;

                case Opcode.ForPrep:
                    // IronBrew's FORPREP handler performs the initial range
                    // check itself. Its encoded target names the companion
                    // FORLOOP, but the out-of-range VM path resumes after that
                    // instruction (the main loop applies its final +1).
                    int loopInstruction = ReferencedTarget(instruction);
                    Add(loopInstruction < 0 ? -1 : loopInstruction + 1);
                    Add(index + 1);
                    break;

                case Opcode.Eq:
                case Opcode.Lt:
                case Opcode.Le:
                case Opcode.Test:
                case Opcode.TestSet:
                case Opcode.TForLoop:
                    int companionTarget = CompanionJumpTarget();
                    if (companionTarget >= 0)
                    {
                        Add(companionTarget);
                        Add(index + 2);
                    }
                    else
                    {
                        Add(index + 1);
                    }
                    break;

                case Opcode.LoadBool when instruction.C != 0:
                    Add(index + 2);
                    break;

                case Opcode.SetList when instruction.C == 0:
                    // The following data word is consumed by SETLIST and is not
                    // dispatched as an instruction by the VM.
                    Add(index + 2);
                    break;

                default:
                    Add(index + 1);
                    break;
            }

            return result;
        }
    }
}
