package com.oshan.checkgate.evaluation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oshan.checkgate.model.FileDiff;
import com.oshan.checkgate.scan.ScanPipelineService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Evaluation runner. Active only with --spring.profiles.active=eval, so it never exists in the deployed service.
 *
 * Reads the evaluation functions (one JSON object per line), wraps each as a "new file" diff, runs it through the
 * real scan pipeline under each condition and run number, and appends one JSON line per run to the output file.
 * Conditions:  with     = the full pipeline, retrieval and the similarity floor included
 *              without  = the same prompt with the standard "no reference entries" text and no retrieval
 *              neutral  = no retrieval, and a plain "no reference entries are provided" line with no instruction
 * Nothing is posted to GitHub. Finished runs are skipped on restart; runs that errored are retried.
 *
 * Settings (all --name=value arguments):  eval.input, eval.output, eval.conditions (default with,without),
 *   eval.runs (3), eval.threads (4), eval.limit (0 = every function; N = first N, for a quick test)
 */
@Component
@Profile("eval")
public class EvaluationRunner implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(EvaluationRunner.class);

    private record Job(JsonNode function, String condition, int run) {
        String key() { return key(function.get("id").asText(), condition, run); }
        static String key(String id, String condition, int run) { return id + "|" + condition + "|" + run; }
    }

    private final ScanPipelineService pipeline;
    private final ConfigurableApplicationContext context;
    private final String input;
    private final String output;
    private final List<String> conditions;
    private final int runs;
    private final int threads;
    private final int limit;
    private final ObjectMapper mapper = new ObjectMapper();
    private BufferedWriter writer;

    public EvaluationRunner(ScanPipelineService pipeline, ConfigurableApplicationContext context,
                            @Value("${eval.input}") String input,
                            @Value("${eval.output}") String output,
                            @Value("${eval.conditions:with,without}") String conditions,
                            @Value("${eval.runs:3}") int runs,
                            @Value("${eval.threads:4}") int threads,
                            @Value("${eval.limit:0}") int limit) {
        this.pipeline = pipeline;
        this.context = context;
        this.input = input;
        this.output = output;
        this.conditions = Arrays.stream(conditions.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
        this.runs = runs;
        this.threads = threads;
        this.limit = limit;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        execute();
        if (context != null) {
            System.exit(SpringApplication.exit(context, () -> 0));
        }
    }

    // The whole evaluation; split from run() so it can be exercised without starting Spring
    public void execute() throws Exception {
        for (String c : conditions) {
            if (!c.equals("with") && !c.equals("without") && !c.equals("neutral")) {
                throw new IllegalArgumentException("Unknown condition '" + c + "' (use with, without and/or neutral)");
            }
        }
        List<JsonNode> functions = readFunctions();
        Set<String> done = readFinishedKeys();

        List<Job> jobs = new ArrayList<>();
        for (int run = 1; run <= runs; run++) {          // run 1 for everything first, so an early stop stays balanced
            for (JsonNode fn : functions) {
                for (String condition : conditions) {
                    Job job = new Job(fn, condition, run);
                    if (!done.contains(job.key())) jobs.add(job);
                }
            }
        }
        log.warn("Evaluation: {} functions, conditions {}, {} runs, {} threads. {} jobs already finished, {} to do.",
                functions.size(), conditions, runs, threads, done.size(), jobs.size());
        if (jobs.isEmpty()) return;

        Path outPath = Path.of(output);
        if (outPath.getParent() != null) Files.createDirectories(outPath.getParent());
        writer = Files.newBufferedWriter(outPath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        AtomicInteger finished = new AtomicInteger();
        AtomicInteger failed = new AtomicInteger();
        long started = System.currentTimeMillis();
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, threads));
        try {
            for (Job job : jobs) {
                pool.submit(() -> {
                    boolean ok = runJob(job);
                    if (!ok) failed.incrementAndGet();
                    int n = finished.incrementAndGet();
                    if (n % 25 == 0 || n == jobs.size()) {
                        long minutes = (System.currentTimeMillis() - started) / 60000;
                        log.warn("Progress: {}/{} jobs, {} failed, {} min elapsed", n, jobs.size(), failed.get(), minutes);
                    }
                });
            }
            pool.shutdown();
            while (!pool.awaitTermination(1, TimeUnit.MINUTES)) { /* wait */ }
        } finally {
            pool.shutdownNow();
            synchronized (this) { writer.close(); }
        }
        log.warn("Evaluation finished: {} jobs, {} failed (run again to retry the failed ones).", finished.get(), failed.get());
    }

    // Returns true if the run produced a result, false if it errored (the error is still written)
    private boolean runJob(Job job) {
        JsonNode fn = job.function();
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("id", fn.get("id").asText());
        record.put("label", fn.path("label").asInt());
        record.put("cwe", fn.path("cwe").asText(""));
        record.put("condition", job.condition());
        record.put("run", job.run());
        record.put("time", Instant.now().toString());
        boolean ok = true;
        try {
            String path = fn.get("file_path").asText();
            FileDiff file = new FileDiff(path, toNewFileDiff(path, fn.get("code").asText()));
            ScanPipelineService.ReferenceMode mode = switch (job.condition()) {
                case "with" -> ScanPipelineService.ReferenceMode.WITH_REFERENCES;
                case "without" -> ScanPipelineService.ReferenceMode.STANDARD_NO_REFERENCES;
                default -> ScanPipelineService.ReferenceMode.NEUTRAL_NO_REFERENCES;
            };
            ScanPipelineService.FileAnalysis a = pipeline.analyzeFile(file, mode);

            record.put("grounded", a.grounded());
            record.put("description", a.description());
            record.put("top_similarity", a.references().isEmpty() ? null : a.references().get(0).similarity());
            List<Map<String, Object>> refs = new ArrayList<>();
            a.references().forEach(r -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", r.id());
                m.put("similarity", r.similarity());
                m.put("title", r.title());
                refs.add(m);
            });
            record.put("retrieved", refs);
            List<Map<String, Object>> findings = new ArrayList<>();
            a.findings().forEach(f -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("type", f.vulnerabilityType());
                m.put("severity", f.severity());
                m.put("reasoning", f.reasoning());
                m.put("line", f.reportedLine());
                m.put("low_confidence", f.lowConfidence());
                findings.add(m);
            });
            record.put("findings", findings);
            record.put("retrieval_ms", a.retrievalMs());
            record.put("analysis_ms", a.analysisMs());
            record.put("error", null);
        } catch (Exception e) {
            ok = false;
            record.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
            log.error("Job {} failed", job.key(), e);
        }
        try {
            append(record);
        } catch (IOException e) {
            log.error("Could not write the result for {}", job.key(), e);
            return false;
        }
        return ok;
    }

    private synchronized void append(Map<String, Object> record) throws IOException {
        writer.write(mapper.writeValueAsString(record));
        writer.newLine();
        writer.flush();
    }

    private List<JsonNode> readFunctions() throws IOException {
        List<JsonNode> out = new ArrayList<>();
        try (var lines = Files.lines(Path.of(input), StandardCharsets.UTF_8)) {
            for (String line : (Iterable<String>) lines::iterator) {
                if (line.isBlank()) continue;
                out.add(mapper.readTree(line));
                if (limit > 0 && out.size() >= limit) break;
            }
        }
        return out;
    }

    // Keys of runs that already finished without an error; errored runs are not counted, so they are retried
    private Set<String> readFinishedKeys() throws IOException {
        Set<String> keys = new HashSet<>();
        Path p = Path.of(output);
        if (!Files.exists(p)) return keys;
        try (var lines = Files.lines(p, StandardCharsets.UTF_8)) {
            for (String line : (Iterable<String>) lines::iterator) {
                if (line.isBlank()) continue;
                JsonNode n = mapper.readTree(line);
                JsonNode err = n.get("error");
                if (err == null || err.isNull()) {
                    keys.add(Job.key(n.get("id").asText(), n.get("condition").asText(), n.get("run").asInt()));
                }
            }
        }
        return keys;
    }

    // Wraps a function as a diff that adds one new file, so the real line numbering sees line 1 as the first line
    // of the function. A reported line therefore matches the labelled vulnerable lines directly.
    static String toNewFileDiff(String path, String code) {
        String[] lines = code.replace("\r\n", "\n").split("\n", -1);
        int n = lines.length;
        if (n > 0 && lines[n - 1].isEmpty()) n--;          // a trailing newline is not another line
        StringBuilder sb = new StringBuilder();
        sb.append("diff --git a/").append(path).append(" b/").append(path).append('\n');
        sb.append("new file mode 100644\n");
        sb.append("--- /dev/null\n");
        sb.append("+++ b/").append(path).append('\n');
        sb.append("@@ -0,0 +1,").append(n).append(" @@\n");
        for (int i = 0; i < n; i++) sb.append('+').append(lines[i]).append('\n');
        return sb.toString();
    }
}
