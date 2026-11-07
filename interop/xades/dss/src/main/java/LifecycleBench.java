import java.lang.management.ManagementFactory;
import java.lang.management.MemoryType;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

/**
 * Times one DSS lifecycle operation from the serialized input to the
 * serialized output, the boundary xml-sec's probes time:
 *
 * <pre>
 * LifecycleBench create PKCS12 PACKAGING DATA TIME OUTPUT
 * LifecycleBench augment INPUT OUTPUT T|LT|LTA ANCHOR EVIDENCE TOKENS [--tsa PKCS12 --tsa-time TIME]
 * LifecycleBench validate INPUT ANCHOR TIME b|t|lt|lta OUTPUT
 * </pre>
 *
 * each with {@code [--detached FILE] [--samples N [--warmups W]]}. Keys, anchors and
 * evidence are loaded once, before any run. Every timestamp comes from
 * {@code TOKENS}: a recorded token answers the identical imprint again, and
 * without {@code --tsa} an unrecorded imprint is refused, so a timed run never
 * acquires. With {@code --samples N} the first run's result is written,
 * {@code W} warmups follow (three by default) and {@code N} runs are timed;
 * the last stdout line reports
 * them, with the JVM's thread allocation, GC and heap counters of the timed
 * runs as a separate block. Without it one run is made, for a cold process.
 */
public class LifecycleBench {
    /** Untimed runs before the samples unless {@code --warmups} asks for another count. */
    private static final int WARMUPS = 3;
    private static int warmups = WARMUPS;

    /** One run of the operation: its serialized result. */
    interface Operation {
        byte[] run() throws Exception;
    }

    /**
     * The recorded timestamps of {@code tokens}, read before any run so that a
     * timed run replays them from memory; acquired only through {@code tsa}.
     */
    static final class Replay implements TSPSource {
        private final transient Path tokens;
        private final transient TSPSource tsa;
        private final transient List<byte[]> imprints = new ArrayList<>();
        private final transient List<TimestampBinary> recorded = new ArrayList<>();
        private int next;

        Replay(Path tokens, TSPSource tsa) throws java.io.IOException {
            this.tokens = tokens;
            this.tsa = tsa;
            while (Files.exists(tokens.resolve(recorded.size() + ".tst"))) {
                int ordinal = recorded.size();
                imprints.add(Files.readAllBytes(tokens.resolve(ordinal + ".imprint")));
                recorded.add(new TimestampBinary(Files.readAllBytes(tokens.resolve(ordinal + ".tst"))));
            }
        }

        /** Every run makes the same requests in the same order. */
        void reset() {
            next = 0;
        }

        @Override
        public TimestampBinary getTimeStampResponse(DigestAlgorithm algorithm, byte[] digest) {
            int ordinal = next++;
            if (ordinal < recorded.size()) {
                if (!Arrays.equals(imprints.get(ordinal), digest)) {
                    throw new DSSException("the imprint differs from recorded token " + ordinal);
                }
                return recorded.get(ordinal);
            }
            if (tsa == null) {
                throw new DSSException("no recorded token and no TSA: this run acquires nothing");
            }
            var binary = tsa.getTimeStampResponse(algorithm, digest);
            try {
                Files.write(tokens.resolve(ordinal + ".imprint"), digest);
                Files.write(tokens.resolve(ordinal + ".tst"), binary.getBytes());
            } catch (java.io.IOException failure) {
                throw new DSSException(failure);
            }
            return binary;
        }
    }

    /** The value of {@code flag}, taken out of {@code args}, or null. */
    private static String take(List<String> args, String flag) {
        int index = args.indexOf(flag);
        if (index < 0) {
            return null;
        }
        String value = args.get(index + 1);
        args.subList(index, index + 2).clear();
        return value;
    }

    private static ValidationLevel level(String level) {
        return switch (level) {
            case "b" -> ValidationLevel.BASIC_SIGNATURES;
            case "t" -> ValidationLevel.TIMESTAMPS;
            case "lt" -> ValidationLevel.LONG_TERM_DATA;
            case "lta" -> ValidationLevel.ARCHIVAL_DATA;
            default -> throw new IllegalArgumentException("the level is b, t, lt or lta");
        };
    }

    public static void main(String[] arguments) throws Exception {
        List<String> args = new ArrayList<>(List.of(arguments));
        String samples = take(args, "--samples");
        String warmupCount = take(args, "--warmups");
        warmups = warmupCount == null ? WARMUPS : Integer.parseInt(warmupCount);
        String detachedPath = take(args, "--detached");
        DSSDocument detached = detachedPath == null ? null : Lifecycle.named(Path.of(detachedPath));
        Integer count = samples == null ? null : Integer.valueOf(samples);
        switch (args.get(0)) {
            case "create" -> {
                var signer = Lifecycle.Signer.load(Path.of(args.get(1)));
                Path data = Path.of(args.get(3));
                byte[] bytes = Files.readAllBytes(data);
                String name = data.getFileName().toString();
                long time = Long.parseLong(args.get(4));
                var service = Lifecycle.signing();
                measure("create", bytes.length, count, Path.of(args.get(5)), () -> DSSUtils.toByteArray(
                    Lifecycle.sign(service, signer, args.get(2), new InMemoryDocument(bytes, name), time)));
            }
            case "augment" -> {
                String tsaStore = take(args, "--tsa");
                String tsaTime = take(args, "--tsa-time");
                Path input = Path.of(args.get(1));
                byte[] bytes = Files.readAllBytes(input);
                String name = input.getFileName().toString();
                var verifier = Lifecycle.verifier(Files.readAllBytes(Path.of(args.get(4))), Path.of(args.get(5)));
                Path tokens = Path.of(args.get(6));
                Files.createDirectories(tokens);
                var replay = new Replay(
                    tokens,
                    tsaStore == null ? null : Lifecycle.tsa(Path.of(tsaStore), Long.parseLong(tsaTime)));
                String step = args.get(3);
                var service = Lifecycle.augmenting(verifier, replay);
                measure("augment-" + step.toLowerCase(), bytes.length, count, Path.of(args.get(2)), () -> {
                    replay.reset();
                    return DSSUtils.toByteArray(
                        Lifecycle.extend(service, new InMemoryDocument(bytes, name), step, detached));
                });
            }
            case "validate" -> {
                Path input = Path.of(args.get(1));
                byte[] bytes = Files.readAllBytes(input);
                String name = input.getFileName().toString();
                var verifier = Lifecycle.verifier(Files.readAllBytes(Path.of(args.get(2))), null);
                long time = Long.parseLong(args.get(3));
                var validation = level(args.get(4));
                measure("validate-" + args.get(4), bytes.length, count, Path.of(args.get(5)), () -> Lifecycle
                    .lines(Lifecycle.validate(new InMemoryDocument(bytes, name), verifier, time, validation, detached))
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            default -> throw new IllegalArgumentException("the operation is create, augment or validate");
        }
    }

    private static long collections() {
        return ManagementFactory.getGarbageCollectorMXBeans().stream()
            .mapToLong(collector -> Math.max(0, collector.getCollectionCount()))
            .sum();
    }

    private static long collectionMillis() {
        return ManagementFactory.getGarbageCollectorMXBeans().stream()
            .mapToLong(collector -> Math.max(0, collector.getCollectionTime()))
            .sum();
    }

    private static String array(long[] values) {
        return Arrays.stream(values).mapToObj(Long::toString).collect(Collectors.joining(",", "[", "]"));
    }

    /**
     * Writes the first run's result to {@code output}; with {@code samples}
     * warms up, times them and prints the report.
     */
    private static void measure(String name, int inputBytes, Integer samples, Path output, Operation operation)
            throws Exception {
        byte[] first = operation.run();
        Files.write(output, first);
        if (samples == null) {
            return;
        }
        for (int warmup = 0; warmup < warmups; warmup++) {
            operation.run();
        }
        var threads = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        var heap = ManagementFactory.getMemoryPoolMXBeans().stream()
            .filter(pool -> pool.getType() == MemoryType.HEAP)
            .toList();
        heap.forEach(pool -> pool.resetPeakUsage());
        long gcBefore = collections();
        long gcMillisBefore = collectionMillis();
        long[] times = new long[samples];
        long[] allocated = new long[samples];
        for (int sample = 0; sample < samples; sample++) {
            // The counters are read outside the timed interval.
            long allocatedBefore = threads.getCurrentThreadAllocatedBytes();
            long start = System.nanoTime();
            operation.run();
            long end = System.nanoTime();
            allocated[sample] = threads.getCurrentThreadAllocatedBytes() - allocatedBefore;
            times[sample] = end - start;
        }
        long heapPeak = heap.stream().mapToLong(pool -> pool.getPeakUsage().getUsed()).sum();
        System.out.println(String.format(
            "{\"engine\":\"dss\",\"operation\":\"%s\",\"samples_ns\":%s,\"allocations\":null,"
                + "\"jvm\":{\"thread_allocated_bytes\":%s,\"gc_collections\":%d,\"gc_millis\":%d,"
                + "\"heap_peak_bytes\":%d},\"input_bytes\":%d,\"output_bytes\":%d}",
            name,
            array(times),
            array(allocated),
            collections() - gcBefore,
            collectionMillis() - gcMillisBefore,
            heapPeak,
            inputBytes,
            first.length));
    }
}
