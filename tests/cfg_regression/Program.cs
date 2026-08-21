using System.Reflection;
using IronBrew2.Bytecode_Library.Bytecode;
using IronBrew2.Bytecode_Library.IR;
using IronBrew2.Obfuscator;
using IronBrew2.Obfuscator.Control_Flow;
using IronBrew2.Obfuscator.VM_Generation;

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

// The automatic planner must select an ordinary, unmarked branching prototype.
{
    Chunk chunk = NewChunk(Opcode.Eq, Opcode.Jmp, Opcode.Move, Opcode.Return, Opcode.Move, Opcode.Return);
    Target(chunk, 1, 4);
    DispatcherFlatteningDecision decision = DispatcherFlatteningPlanner.Apply(chunk);
    Expect(decision.IsEligible, $"ordinary branch prototype rejected: {decision.Reason}");
    Expect(chunk.DispatcherFlattened, "eligible prototype was not marked for dispatcher flattening");
    Expect(decision.Graph.Blocks.Count >= 2, "eligible prototype did not have multiple route blocks");
}

// Unsupported shapes must fall back atomically instead of receiving a partial
// route representation.
{
    Chunk chunk = NewChunk(Opcode.Eq, Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Return);
    DispatcherFlatteningDecision decision = DispatcherFlatteningPlanner.Apply(chunk);
    Expect(!decision.IsEligible, "comparison without companion JMP was accepted");
    Expect(!chunk.DispatcherFlattened, "malformed prototype retained a dispatcher marker");
    Expect(decision.Reason == "invalid-skip-next-companion", "unexpected malformed-comparison fallback reason");
}
{
    Chunk chunk = NewChunk(Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Return);
    DispatcherFlatteningDecision decision = DispatcherFlatteningPlanner.Apply(chunk);
    Expect(!decision.IsEligible && decision.Reason == "single-block", "single-block fallback failed");
}

// SETLIST's data word is supported when complete and rejected when truncated.
{
    Chunk chunk = NewChunk(Opcode.SetList, Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Return);
    chunk.Instructions[0].C = 0;
    chunk.Instructions[1].InstructionType = InstructionType.Data;
    DispatcherFlatteningDecision decision = DispatcherFlatteningPlanner.Apply(chunk);
    Expect(decision.IsEligible, $"valid SETLIST data word rejected: {decision.Reason}");
}
{
    Chunk chunk = NewChunk(Opcode.SetList, Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Move, Opcode.Return);
    chunk.Instructions[0].C = 0;
    DispatcherFlatteningDecision decision = DispatcherFlatteningPlanner.Apply(chunk);
    Expect(!decision.IsEligible && decision.Reason == "invalid-setlist-data-word", "truncated SETLIST fallback failed");
}

// Closure upvalue pseudo instructions are analyzed as one complete shape. This
// remains eligible even when later serializer paging puts bindings in a new block.
{
    Chunk child = NewChunk(Opcode.Return);
    child.UpvalueCount = 1;
    Chunk chunk = NewChunk(Opcode.Closure, Opcode.Move, Opcode.Eq, Opcode.Jmp, Opcode.Move, Opcode.Return, Opcode.Return);
    chunk.Functions.Add(child);
    chunk.Instructions[0].RefOperands[0] = child;
    Target(chunk, 3, 6);
    DispatcherFlatteningDecision decision = DispatcherFlatteningPlanner.Apply(chunk);
    Expect(decision.IsEligible, $"valid closure bindings rejected: {decision.Reason}");

    chunk.Instructions[1].OpCode = Opcode.Add;
    decision = DispatcherFlatteningPlanner.Apply(chunk);
    Expect(!decision.IsEligible && decision.Reason == "invalid-closure-binding", "invalid closure binding fallback failed");
}

// All three dispatcher structures must be reachable from the dedicated purpose
// stream, and equal roots must select the same template without consulting any
// process-global random source.
{
    var templates = new HashSet<DispatcherTemplate>();
    for (int discriminator = 0; discriminator < 256; discriminator++)
    {
        byte[] root = Enumerable.Range(0, 32)
            .Select(value => (byte)(value ^ discriminator))
            .ToArray();
        using var first = new BuildSeed(root);
        using var second = new BuildSeed(root);
        DispatcherTemplate selected = DispatcherTemplateSelector.Select(first.GetStream("dispatcher.template"));
        DispatcherTemplate repeated = DispatcherTemplateSelector.Select(second.GetStream("dispatcher.template"));
        Expect(selected == repeated, "equal build roots selected different dispatcher templates");
        Expect((int)selected >= 0 && (int)selected < DispatcherTemplateSelector.TemplateCount,
            "dispatcher template selector escaped its declared range");
        templates.Add(selected);
    }
    Expect(templates.SetEquals(Enum.GetValues<DispatcherTemplate>()),
        $"dispatcher selector did not cover all templates: {string.Join(',', templates)}");
}

// All three VM state-carrier topologies must be reachable from the dedicated
// purpose stream and reproducible from the same master root.
{
    var layouts = new HashSet<VMLayout>();
    for (int discriminator = 0; discriminator < 256; discriminator++)
    {
        byte[] root = Enumerable.Range(0, 32)
            .Select(value => (byte)(value ^ discriminator))
            .ToArray();
        using var first = new BuildSeed(root);
        using var second = new BuildSeed(root);
        VMLayout selected = VMLayoutSelector.Select(first.GetStream("vm.layout"));
        VMLayout repeated = VMLayoutSelector.Select(second.GetStream("vm.layout"));
        Expect(selected == repeated, "equal build roots selected different VM layouts");
        Expect((int)selected >= 0 && (int)selected < VMLayoutSelector.TemplateCount,
            "VM layout selector escaped its declared range");
        layouts.Add(selected);
    }
    Expect(layouts.SetEquals(Enum.GetValues<VMLayout>()),
        $"VM layout selector did not cover all templates: {string.Join(',', layouts)}");
}

// One master BuildSeed must deterministically derive independent named streams.
// Re-requesting a name continues the same stream instead of replaying bytes.
{
    byte[] root = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
    using var seedA = new BuildSeed(root);
    using var seedB = new BuildSeed(root);
    BuildRandom opcodeA = seedA.GetStream("opcode");
    BuildRandom opcodeB = seedB.GetStream("opcode");
    byte[] firstA = opcodeA.GetBytes(96);
    byte[] firstB = opcodeB.GetBytes(96);
    Expect(firstA.SequenceEqual(firstB), "equal build roots did not reproduce a purpose stream");
    Expect(ReferenceEquals(opcodeA, seedA.GetStream("opcode")), "purpose stream was restarted instead of continued");
    Expect(opcodeA.GetBytes(64).SequenceEqual(opcodeB.GetBytes(64)), "continued purpose streams diverged");

    byte[] layout = seedA.GetStream("vm.layout").GetBytes(96);
    Expect(!firstA.SequenceEqual(layout), "different build purposes produced the same stream");
    for (int index = 0; index < 10000; index++)
    {
        int signed = opcodeA.Next(-37, 91);
        long wide = opcodeA.NextInt64(-5000000000L, 9000000000L);
        Expect(signed >= -37 && signed < 91, "BuildRandom int range escaped its bounds");
        Expect(wide >= -5000000000L && wide < 9000000000L, "BuildRandom int64 range escaped its bounds");
    }
}

// Final opcode-placeholder lowering runs after payload carrier insertion. It
// must rewrite executable spans without touching Base91/string/comment bytes
// that happen to contain the same OP_A/OP_B/OP_C spellings.
{
    MethodInfo rewriteMethod = typeof(Generator).GetMethod(
        "RewriteExecutableLuaSpans",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("executable Lua span rewriter not found");
    Func<string, string> lower = segment => segment
        .Replace("OP_ENUM", "1")
        .Replace("OP_A", "2")
        .Replace("OP_B", "3")
        .Replace("OP_C", "4");
    string input = "local a=OP_A;local s='OP_A';local d=\"OP_B\";"
        + "local e='x\\\'OP_C';-- OP_ENUM OP_A\n"
        + "local l=[=[OP_B OP_C]=];--[==[OP_A OP_ENUM]==]\n"
        + "return OP_ENUM+OP_B+OP_C;";
    string expected = "local a=2;local s='OP_A';local d=\"OP_B\";"
        + "local e='x\\\'OP_C';-- OP_ENUM OP_A\n"
        + "local l=[=[OP_B OP_C]=];--[==[OP_A OP_ENUM]==]\n"
        + "return 1+3+4;";
    string actual = (string)(rewriteMethod.Invoke(null, new object[] { input, lower })
        ?? throw new InvalidOperationException("executable Lua span rewriter returned null"));
    Expect(actual == expected, "opcode placeholder lowering modified a protected Lua span");
}

Console.WriteLine("PASS CFG, dispatcher planner, executable-span and BuildSeed regression");
