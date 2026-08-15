using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;

static Chunk NewChunk(params Opcode[] opcodes)
{
    var chunk = new Chunk
    {
        Instructions = new List<Instruction>(),
        Constants = new List<Constant>(),
        Functions = new List<Chunk>(),
        Upvalues = new List<string>()
    };
    foreach (Opcode opcode in opcodes)
        chunk.Instructions.Add(new Instruction(chunk, opcode));
    return chunk;
}

static void Target(Chunk chunk, int source, int target)
{
    chunk.Instructions[source].RefOperands[0] = chunk.Instructions[target];
}

static ControlFlowBlock BlockAt(ControlFlowGraph graph, int instructionIndex) =>
    graph.Blocks.Single(block => instructionIndex >= block.Start && instructionIndex < block.EndExclusive);

static void ExpectSuccessors(ControlFlowBlock block, params int[] expected)
{
    int[] actual = block.Successors.Select(successor => successor.Start).OrderBy(value => value).ToArray();
    int[] wanted = expected.OrderBy(value => value).ToArray();
    if (!actual.SequenceEqual(wanted))
        throw new InvalidOperationException(
            $"block [{block.Start},{block.EndExclusive}) successors [{string.Join(',', actual)}], expected [{string.Join(',', wanted)}]");
}

static void Expect(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

// A direct JMP self-loop must be represented as an explicit self-edge.
{
    Chunk chunk = NewChunk(Opcode.Jmp);
    Target(chunk, 0, 0);
    ControlFlowGraph graph = ControlFlowGraph.Build(chunk, 24);
    Expect(graph.Blocks.Count == 1, "self-loop should contain one block");
    ExpectSuccessors(graph.Blocks[0], 0);
    Expect(graph.Blocks[0].Predecessors.Single() == graph.Blocks[0], "self-loop predecessor missing");
}

// Comparison and TFORLOOP opcodes consume their companion JMP. The VM can
// continue at the JMP target or skip both words, but never dispatches the
// companion merely because the comparison executed.
foreach (Opcode opcode in new[] { Opcode.Eq, Opcode.Lt, Opcode.Le, Opcode.Test, Opcode.TestSet, Opcode.TForLoop })
{
    Chunk chunk = NewChunk(opcode, Opcode.Jmp, Opcode.Move, Opcode.Return, Opcode.Return);
    Target(chunk, 1, 4);
    ControlFlowGraph graph = ControlFlowGraph.Build(chunk, 24);
    ExpectSuccessors(BlockAt(graph, 0), 2, 4);
    Expect(BlockAt(graph, 1).Start == 1, $"{opcode} companion JMP is not a leader");
}

// IronBrew's FORPREP optimization bypasses the companion FORLOOP on the
// out-of-range path. Its target is therefore the word after FORLOOP. The body
// block also has a genuine self-edge through FORLOOP.
{
    Chunk chunk = NewChunk(Opcode.ForPrep, Opcode.Move, Opcode.Move, Opcode.ForLoop, Opcode.Return);
    Target(chunk, 0, 3);
    Target(chunk, 3, 1);
    ControlFlowGraph graph = ControlFlowGraph.Build(chunk, 24);
    ExpectSuccessors(BlockAt(graph, 0), 1, 4);
    ExpectSuccessors(BlockAt(graph, 3), 1, 4);
    Expect(BlockAt(graph, 1) == BlockAt(graph, 3), "loop body and FORLOOP should share the natural block");
}

// Skip-next opcodes and SETLIST's data word must not create a dispatch edge to
// the skipped/consumed word.
{
    Chunk chunk = NewChunk(Opcode.LoadBool, Opcode.Move, Opcode.SetList, Opcode.Move, Opcode.Return);
    chunk.Instructions[0].C = 1;
    chunk.Instructions[2].C = 0;
    chunk.Instructions[3].InstructionType = InstructionType.Data;
    ControlFlowGraph graph = ControlFlowGraph.Build(chunk, 24);
    ExpectSuccessors(BlockAt(graph, 0), 2);
    ExpectSuccessors(BlockAt(graph, 2), 4);
    ExpectSuccessors(BlockAt(graph, 3));
}

// Artificial paging may subdivide a straight natural region, but must preserve
// a real fallthrough edge between the resulting blocks.
{
    Chunk chunk = NewChunk(Enumerable.Repeat(Opcode.Move, 25).Append(Opcode.Return).ToArray());
    ControlFlowGraph graph = ControlFlowGraph.Build(chunk, 24);
    Expect(graph.Blocks.Count == 2, "24-instruction subdivision was not applied");
    Expect(graph.Blocks[0].Start == 0 && graph.Blocks[0].EndExclusive == 24, "unexpected first page bounds");
    Expect(graph.Blocks[1].Start == 24 && graph.Blocks[1].EndExclusive == 26, "unexpected second page bounds");
    ExpectSuccessors(graph.Blocks[0], 24);
    ExpectSuccessors(graph.Blocks[1]);
}

Console.WriteLine("PASS CFG structural regression");
