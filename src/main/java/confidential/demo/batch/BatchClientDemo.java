package confidential.demo.batch;

import confidential.client.BatchClientProxy;
import confidential.client.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;

import java.util.Random;

/**
 * Demo class showing how to use BatchClientProxy for batch block processing.
 * 
 * This demonstrates the key optimization:
 * - Instead of creating N separate polynomials and commitments for N blocks,
 *   blocks are aggregated into batches and each batch uses a SINGLE polynomial
 *   and commitment.
 */
public class BatchClientDemo {
    private static final Logger logger = LoggerFactory.getLogger("demo");
    private static final Random random = new Random();

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: BatchClientDemo <clientId> [batchSize] [parallelLevel]");
            System.exit(1);
        }
        
        int clientId = Integer.parseInt(args[0]);
        int batchSize = args.length > 1 ? Integer.parseInt(args[1]) : BatchClientProxy.DEFAULT_BATCH_SIZE;
        int parallelLevel = args.length > 2 ? Integer.parseInt(args[2]) : BatchClientProxy.DEFAULT_PARALLEL_LEVEL;
        
        try {
            BatchClientProxy batchClient = new BatchClientProxy(clientId, batchSize, parallelLevel);
            runBatchDemo(batchClient);
            batchClient.close();
        } catch (SecretSharingException e) {
            logger.error("Failed to initialize batch client", e);
        }
    }

    private static void runBatchDemo(BatchClientProxy batchClient) {
        System.out.println("========================================");
        System.out.println("  Batch Client Demo");
        System.out.println("  Batch Size: " + batchClient.getBatchSize());
        System.out.println("  Parallel Level: " + batchClient.getParallelLevel());
        System.out.println("========================================");

        try {
            // ========== Demo 1: Process a batch of blocks ==========
            System.out.println("\n--- Demo 1: Batch processing of multiple blocks ---");
            
            // Generate test blocks (simulating confidential data)
            byte[][] blocks = generateTestBlocks(15, 64); // 15 blocks, 64 bytes each
            System.out.println("Generated " + blocks.length + " blocks for batch processing");
            
            // Process with batch optimization
            // Blocks are aggregated into batches of batchSize
            // Each batch generates only ONE polynomial + commitment
            long startTime = System.nanoTime();
            
            Response response = batchClient.invokeOrderedBatch(
                    "batch_operation".getBytes(),
                    blocks
            );
            
            long endTime = System.nanoTime();
            double durationMs = (endTime - startTime) / 1_000_000.0;
            
            if (response != null) {
                System.out.println("Batch operation completed in " + String.format("%.2f", durationMs) + " ms");
                System.out.println("Plain response: " + new String(response.getPlainData() != null ? response.getPlainData() : new byte[0]));
                if (response.getConfidentialData() != null) {
                    System.out.println("Confidential responses: " + response.getConfidentialData().length);
                    for (int i = 0; i < response.getConfidentialData().length; i++) {
                        System.out.println("  Response[" + i + "]: " + response.getConfidentialData()[i].length + " bytes");
                    }
                }
            } else {
                System.out.println("Batch operation returned null (expected if no BFT cluster is running)");
            }
            
            // ========== Demo 2: Single block (no batching needed) ==========
            System.out.println("\n--- Demo 2: Single block (falls back to standard) ---");
            Response singleResponse = batchClient.invokeOrderedBatch(
                    "single_op".getBytes(),
                    "Hello, World!".getBytes()
            );
            System.out.println("Single block response: " + (singleResponse != null ? "ok" : "null"));
            
            System.out.println("\n========================================");
            System.out.println("  Demo Completed");
            System.out.println("========================================");
            
        } catch (Exception e) {
            logger.error("Demo failed", e);
        }
    }

    /**
     * Generates random test blocks for demo purposes.
     */
    private static byte[][] generateTestBlocks(int count, int blockSize) {
        byte[][] blocks = new byte[count][blockSize];
        for (int i = 0; i < count; i++) {
            random.nextBytes(blocks[i]);
        }
        return blocks;
    }

    /**
     * Helper method to create a simple non-batch client proxy for comparison.
     * This shows the difference between standard (N polynomials) and batch (1 polynomial per batch) approaches.
     */
    public static void comparePerformance(int clientId, int numBlocks, int blockSize) 
            throws SecretSharingException {
        System.out.println("\n--- Performance Comparison ---");
        System.out.println("Standard:   Each block generates its own polynomial + commitment");
        System.out.println("Batch:      Blocks are aggregated; one polynomial + commitment per batch");
        System.out.println("Number of blocks: " + numBlocks);
        System.out.println("Block size: " + blockSize + " bytes");
        System.out.println("  -> Standard requires " + numBlocks + " polynomial generations");
        int numBatches = (int) Math.ceil((double) numBlocks / BatchClientProxy.DEFAULT_BATCH_SIZE);
        System.out.println("  -> Batch requires only " + numBatches + " polynomial generations");
        System.out.println("  -> Optimization factor: ~" + (numBlocks / Math.max(1, numBatches)) + "x reduction");
    }
}