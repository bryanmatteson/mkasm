import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import generic.jar.ResourceFile;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.util.DefaultLanguageService;
import java.io.*;
import java.math.BigInteger;
import java.util.*;

/** Optional independent Ghidra oracle. One JSON request and response per line. */
public class CodecOracle {
    private static JsonObject encodingPattern(AssemblyResolvedPatterns patterns) {
        var result = new JsonObject();
        var instruction = patterns.getInstruction();
        result.addProperty("value", HexFormat.of().formatHex(instruction.getValsAll()));
        result.addProperty("mask", HexFormat.of().formatHex(instruction.getMaskAll()));
        result.addProperty("length", patterns.getInstructionLength());
        result.addProperty("defined_length", patterns.getDefinedInstructionLength());
        return result;
    }
    public static void main(String[] args) throws Exception {
        PrintStream protocol = System.out;
        // Ghidra initialization and processor diagnostics belong on stderr.
        System.setOut(System.err);
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var languages = new HashMap<String, Language>();
        var assemblers = new HashMap<String, Assembler>();
        var providers = new HashMap<String, SleighLanguageProvider>();
        var reader = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = reader.readLine()) != null) {
            var response = new JsonObject();
            try {
                var request = JsonParser.parseString(line).getAsJsonObject();
                if (request.has("id")) response.add("id", request.get("id"));
                if (request.has("list_languages") && request.get("list_languages").getAsBoolean()) {
                    var ids = new TreeSet<String>();
                    for (var description : DefaultLanguageService.getLanguageService().getLanguageDescriptions(false))
                        ids.add(description.getLanguageID().toString());
                    var array = new JsonArray();
                    ids.forEach(array::add);
                    response.add("languages", array);
                    protocol.println(response);
                    continue;
                }
                String id = request.get("language").getAsString();
                String definitions = request.has("language_definitions")
                    ? new File(request.get("language_definitions").getAsString()).getCanonicalPath() : "";
                String cacheKey = definitions + "\n" + id;
                Language language = languages.get(cacheKey);
                if (language == null) {
                    if (definitions.isEmpty()) {
                        language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
                    } else {
                        var provider = providers.get(definitions);
                        if (provider == null) {
                            var constructor = SleighLanguageProvider.class.getDeclaredConstructor(ResourceFile.class);
                            constructor.setAccessible(true);
                            provider = constructor.newInstance(new ResourceFile(new File(definitions)));
                            providers.put(definitions, provider);
                        }
                        language = provider.getLanguage(new LanguageID(id));
                        if (language == null) throw new IllegalArgumentException("language absent from custom definitions: " + id);
                    }
                    languages.put(cacheKey, language);
                }
                long offset = request.has("address") ? Long.decode(request.get("address").getAsString()) : 0;
                var address = language.getDefaultSpace().getAddress(offset);
                if (request.has("assembly")) {
                    Assembler assembler = assemblers.get(cacheKey);
                    if (assembler == null) {
                        assembler = Assemblers.getAssembler(language);
                        assemblers.put(cacheKey, assembler);
                    }
                    var context = assembler.getContextAt(address);
                    if (request.has("context")) {
                        for (var entry : request.getAsJsonObject("context").entrySet()) {
                            var register = language.getRegister(entry.getKey());
                            if (register == null) throw new IllegalArgumentException("unknown context register " + entry.getKey());
                            var value = new RegisterValue(register, new BigInteger(entry.getValue().getAsString()));
                            context = context.assign(AssemblyPatternBlock.fromRegisterValue(value));
                        }
                    }
                    // assign may trim unused leading/trailing bytes. The
                    // assembler's public overload requires a complete context.
                    var base = language.getContextBaseRegister();
                    int contextSize = base == null ? 0 : base.getMinimumByteSize();
                    context = AssemblyPatternBlock.fromBytes(0,
                        Arrays.copyOf(context.getValsAll(), contextSize));
                    if (request.has("all_encodings") && request.get("all_encodings").getAsBoolean()) {
                        // Ask Ghidra's solver for every legal encoding, rather
                        // than treating its default alias choice as unique.
                        // No expected bytes are supplied to this calculation.
                        var candidates = new JsonArray();
                        for (var resolution : assembler.resolveLine(address, request.get("assembly").getAsString(), context)) {
                            if (!(resolution instanceof AssemblyResolvedPatterns patterns) || patterns.hasBackfills() || patterns.getContext().combine(context) == null) continue;
                            var candidate = encodingPattern(patterns);
                            var forbidden = new JsonArray();
                            for (var excluded : patterns.getForbids()) {
                                if (excluded.getContext().combine(context) != null) forbidden.add(encodingPattern(excluded));
                            }
                            candidate.add("forbidden", forbidden);
                            candidates.add(candidate);
                        }
                        // Return solver constraints rather than expanding
                        // unconstrained padding bits into millions of bytes.
                        response.add("encoding_patterns", candidates);
                    }
                    response.addProperty("encoded", HexFormat.of().formatHex(
                        assembler.assembleLine(address, request.get("assembly").getAsString(), context)));
                }
                if (request.has("bytes")) {
                    byte[] bytes = HexFormat.of().parseHex(request.get("bytes").getAsString());
                    var context = new ProcessorContextImpl(language);
                    if (request.has("context")) {
                        for (var entry : request.getAsJsonObject("context").entrySet()) {
                            var register = language.getRegister(entry.getKey());
                            if (register == null) throw new IllegalArgumentException("unknown context register " + entry.getKey());
                            context.setValue(register, new BigInteger(entry.getValue().getAsString()));
                        }
                    }
                    var buffer = new ByteMemBufferImpl(address, bytes, language.isBigEndian());
                    var prototype = language.parse(buffer, context, false);
                    var instruction = new PseudoInstruction(address, prototype, buffer, context);
                    response.addProperty("length", instruction.getLength());
                    response.addProperty("mnemonic", instruction.getMnemonicString());
                    response.addProperty("text", instruction.toString());
                    response.addProperty("flow", instruction.getFlowType().toString());
                    response.addProperty("delay_slots", instruction.getDelaySlotDepth());
                }
            } catch (Exception error) {
                response.addProperty("error", error.getClass().getSimpleName() + ": " + error.getMessage());
            }
            protocol.println(response);
        }
        System.exit(0);
    }
}
