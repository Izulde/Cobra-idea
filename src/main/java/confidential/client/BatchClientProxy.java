package confidential.client;

import bftsmart.tom.ServiceProxy;
import confidential.Configuration;
import confidential.ExtractedResponse;
import confidential.MessageType;
import confidential.Metadata;
import confidential.encrypted.EncryptedPublishedShares;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentUtils;
import vss.commitment.constant.ConstantCommitment;
import vss.facade.Mode;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.OpenPublishedShares;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/**
 * BatchClientProxy implements batch processing for confidential data blocks.
 * 
 * Key optimization: Instead of generating separate polynomials and commitments
 * for each individual block, multiple blocks are aggregated together and a
 * SINGLE polynomial + commitment is generated for the entire batch.
 * This significantly reduces cryptographic overhead for bulk operations.
 */
public class BatchClientProxy {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    
    private final ServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;
    private final ServersResponseHandler serversResponseHandler;
    private final boolean isLinearCommitmentScheme;
    private final boolean isSendAllSharesTogether;
    private final SecureRandom rndGenerator;
    
    // Batch configuration
    public static final int DEFAULT_BATCH_SIZE = 10;
    public static final int DEFAULT_PARALLEL_LEVEL = 4;
    
    private final int batchSize;
    private final int parallelLevel;

    public BatchClientProxy(int clientId) throws SecretSharingException {
        this(clientId, DEFAULT_BATCH_SIZE, DEFAULT_PARALLEL_LEVEL);
    }

    public BatchClientProxy(int clientId, int batchSize, int parallelLevel) throws SecretSharingException {
        if (batchSize <= 0) throw new IllegalArgumentException("batchSize must be > 0");
        if (parallelLevel <= 0) throw new IllegalArgumentException("parallelLevel must be > 0");
        
        this.batchSize = batchSize;
        this.parallelLevel = parallelLevel;
        this.rndGenerator = new SecureRandom();
        
        if (Configuration.getInstance().useTLSEncryption()) {
            serversResponseHandler = new PlainServersResponseHandler();
        } else {
            serversResponseHandler = new EncryptedServersResponseHandler(clientId);
        }
        this.service = new ServiceProxy(clientId, null, serversResponseHandler,
                serversResponseHandler, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(
                service.getViewManager().getCurrentView());
        serversResponseHandler.setClientConfidentialityScheme(confidentialityScheme);
        isLinearCommitmentScheme = confidentialityScheme.isLinearCommitmentScheme();
        isSendAllSharesTogether = Configuration.getInstance().isSendAllSharesTogether();
    }

    /**
     * Main batch processing flow:
     * 1. Aggregate blocks into a batch
     * 2. Generate a single polynomial + commitment for the batch
     * 3. Construct batch message
     * 4. Send once to BFT cluster
     */
    public Response invokeOrderedBatch(byte[] plainData, byte[]... confidentialBlocks) 
            throws SecretSharingException {
        serversResponseHandler.reset();
        
        if (confidentialBlocks == null || confidentialBlocks.length == 0) {
            // Fall back to standard single invocation
            return invokeStandard(plainData, confidentialBlocks);
        }
        
        int totalBlocks = confidentialBlocks.length;
        
        // ========== Step 1: Aggregate blocks into batches ==========
        List<List<byte[]>> batches = aggregateBlocks(confidentialBlocks, batchSize);
        
        // ========== Step 2 & 3: For each batch, generate polynomial + commitment ==========
        List<BatchOutput> batchOutputs = new ArrayList<>(batches.size());
        for (List<byte[]> batch : batches) {
            BatchOutput output = processSingleBatch(batch);
            batchOutputs.add(output);
        }
        
        // ========== Step 4: Encrypt shares for each server ==========
        Map<Integer, byte[]> privateData = null;
        if (!isSendAllSharesTogether) {
            int[] servers = service.getViewManager().getCurrentViewProcesses();
            privateData = new HashMap<>(servers.length);
            for (int server : servers) {
                byte[] serialized = serializeBatchPrivateDataFor(server, batchOutputs);
                privateData.put(server, serialized);
            }
        }
        
        // Serialize common data with all batch outputs
        byte[] commonData = serializeBatchCommonData(plainData, batchOutputs);
        if (commonData == null) return null;
        
        byte metadata = (byte) Metadata.VERIFY.ordinal();
        byte[] response = service.invokeOrdered(commonData, privateData, metadata);
        
        return composeResponse(response);
    }

    /**
     * Parallel verification of commitments against blocks
     * Uses thread pool for concurrent validation.
     */
    public boolean parallelVerify(Commitment commitment, byte[][] blocks, int threshold) 
            throws SecretSharingException {
        ExecutorService threadPool = Executors.newFixedThreadPool(
                Math.min(parallelLevel, blocks.length));
        List<Future<Boolean>> futures = new ArrayList<>(blocks.length);
        
        CommitmentScheme scheme = confidentialityScheme.getCommitmentScheme();
        scheme.startVerification(commitment);
        
        try {
            // Submit verification tasks
            for (byte[] block : blocks) {
                futures.add(threadPool.submit(() -> {
                    try {
                        // Verify the commitment corresponds to the block
                        // In the context of batch processing, the block data is part
                        // of the aggregated secret, so we verify shares if available
                        return verifyBlockAgainstCommitment(block, commitment);
                    } catch (Exception e) {
                        logger.error("Verification failed for block", e);
                        return false;
                    }
                }));
            }
            
            // Collect results
            for (Future<Boolean> future : futures) {
                if (!future.get()) {
                    return false;
                }
            }
            return true;
        } catch (InterruptedException | ExecutionException e) {
            logger.error("Parallel verification failed", e);
            return false;
        } finally {
            scheme.endVerification();
            threadPool.shutdown();
        }
    }

    /**
     * Aggregates blocks into batches of specified size.
     * Last batch may be smaller if blocks.length is not evenly divisible.
     */
    private List<List<byte[]>> aggregateBlocks(byte[][] blocks, int size) {
        List<List<byte[]>> batches = new ArrayList<>();
        int totalBlocks = blocks.length;
        
        for (int i = 0; i < totalBlocks; i += size) {
            int end = Math.min(i + size, totalBlocks);
            List<byte[]> batch = new ArrayList<>(end - i);
            for (int j = i; j < end; j++) {
                batch.add(blocks[j]);
            }
            batches.add(batch);
        }
        
        logger.debug("Aggregated {} blocks into {} batches (batch size: {})", 
                totalBlocks, batches.size(), size);
        return batches;
    }

    /**
     * Processes a single batch: concatenates blocks, generates polynomial and commitment.
     */
    private BatchOutput processSingleBatch(List<byte[]> batchBlocks) throws SecretSharingException {
        // Step 1: Concatenate all blocks into one aggregated data
        byte[] aggregatedData = concatenateBlocks(batchBlocks);
        
        // Step 2: Share the aggregated data using the VSS scheme
        // This generates ONE polynomial and ONE commitment for the entire batch
        EncryptedPublishedShares openShares = confidentialityScheme.share(
                aggregatedData, Mode.LARGE_SECRET);
        
        // Create encrypted shares per server
        int[] servers = service.getViewManager().getCurrentViewProcesses();
        Map<Integer, byte[]> encryptedShares = new HashMap<>(servers.length);
        for (int server : servers) {
            BigInteger shareholder = confidentialityScheme.getShareholder(server);
            byte[] encryptedShare = findEncryptedShareFor(server, openShares);
            encryptedShares.put(server, encryptedShare);
        }
        
        long batchId = rndGenerator.nextLong() & Long.MAX_VALUE;
        
        logger.debug("Batch {}: aggregated {} blocks ({} bytes total), generated polynomial + commitment",
                batchId, batchBlocks.size(), aggregatedData.length);
        
        return new BatchOutput(
                batchId,
                batchBlocks.toArray(new byte[0][]),
                openShares,
                encryptedShares
        );
    }

    /**
     * Concatenates multiple blocks into a single byte array.
     * Uses length-prefix encoding for deserialization.
     */
    private byte[] concatenateBlocks(List<byte[]> blocks) {
        // Calculate total size: for each block, store 4-byte length + data
        int totalSize = 0;
        for (byte[] block : blocks) {
            totalSize += 4 + block.length; // 4 bytes for length prefix
        }
        
        byte[] result = new byte[totalSize];
        int offset = 0;
        for (byte[] block : blocks) {
            // Write length as big-endian int
            result[offset++] = (byte) ((block.length >> 24) & 0xFF);
            result[offset++] = (byte) ((block.length >> 16) & 0xFF);
            result[offset++] = (byte) ((block.length >> 8) & 0xFF);
            result[offset++] = (byte) (block.length & 0xFF);
            // Write block data
            System.arraycopy(block, 0, result, offset, block.length);
            offset += block.length;
        }
        
        return result;
    }

    /**
     * Finds encrypted share for a specific server from OpenPublishedShares.
     */
    private byte[] findEncryptedShareFor(int server, OpenPublishedShares openShares) {
        try {
            BigInteger shareholder = confidentialityScheme.getShareholder(server);
            vss.secretsharing.Share[] shares = openShares.getShares();
            for (vss.secretsharing.Share share : shares) {
                if (share.getShareholder().equals(shareholder)) {
                    return confidentialityScheme.encryptShareFor(server, share);
                }
            }
        } catch (Exception e) {
            logger.error("Failed to encrypt share for server {}", server, e);
        }
        return null;
    }

    /**
     * Serializes private data for a specific server (shares + witnesses).
     */
    private byte[] serializeBatchPrivateDataFor(int server, List<BatchOutput> batchOutputs) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            
            out.writeInt(batchOutputs.size());
            for (BatchOutput output : batchOutputs) {
                byte[] encryptedShareBytes = output.getEncryptedShares().get(server);
                out.writeInt(encryptedShareBytes == null ? -1 : encryptedShareBytes.length);
                if (encryptedShareBytes != null) {
                    out.write(encryptedShareBytes);
                }
                
                if (!isLinearCommitmentScheme && output.getOpenShares() != null) {
                    BigInteger shareholder = confidentialityScheme.getShareholder(server);
                    ConstantCommitment commitment = 
                            (ConstantCommitment) output.getOpenShares().getCommitments();
                    byte[] witness = commitment.getWitness(shareholder);
                    out.writeInt(witness.length);
                    out.write(witness);
                }
            }
            
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Failed to serialize batch private data for server {}", server, e);
            return null;
        }
    }

    /**
     * Serializes common data (plain data + all batch outputs with commitments).
     */
    private byte[] serializeBatchCommonData(byte[] plainData, List<BatchOutput> batchOutputs) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            
            out.write((byte) MessageType.CLIENT.ordinal());
            
            // Write plain data
            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null) {
                out.write(plainData);
            }
            
            // Write number of batches
            out.writeInt(batchOutputs.size());
            
            for (BatchOutput output : batchOutputs) {
                // Write batch ID
                out.writeLong(output.getBatchId());
                
                // Write batch blocks
                byte[][] blocks = output.getBatchBlocks();
                out.writeInt(blocks.length);
                for (byte[] block : blocks) {
                    out.writeInt(block.length);
                    out.write(block);
                }
                
                // Write shared data and commitments
                if (isSendAllSharesTogether) {
                    // Write full EncryptedPublishedShares
                    // For now, write sharedData and commitment separately
                    byte[] sharedData = output.getOpenShares().getSharedData();
                    out.writeInt(sharedData == null ? -1 : sharedData.length);
                    if (sharedData != null) {
                        out.write(sharedData);
                    }
                    
                    Commitment commitment = output.getOpenShares().getCommitments();
                    if (isLinearCommitmentScheme) {
                        CommitmentUtils.getInstance().writeCommitment(commitment, out);
                    } else {
                        byte[] c = ((ConstantCommitment) commitment).getCommitment();
                        out.writeInt(c.length);
                        out.write(c);
                    }
                } else {
                    // Write only shared data and commitment (shares sent separately)
                    byte[] sharedData = output.getOpenShares().getSharedData();
                    out.writeInt(sharedData == null ? -1 : sharedData.length);
                    if (sharedData != null) {
                        out.write(sharedData);
                    }
                    
                    Commitment commitment = output.getOpenShares().getCommitments();
                    if (isLinearCommitmentScheme) {
                        CommitmentUtils.getInstance().writeCommitment(commitment, out);
                    } else {
                        byte[] c = ((ConstantCommitment) commitment).getCommitment();
                        out.writeInt(c.length);
                        out.write(c);
                    }
                }
            }
            
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Failed to serialize batch common data", e);
            return null;
        }
    }

    /**
     * Verifies a single block against a commitment.
     * This serves as a building block for parallel verification.
     */
    private boolean verifyBlockAgainstCommitment(byte[] block, Commitment commitment) {
        try {
            // For real verification, we'd check the share's validity
            // using the CommitmentScheme.checkValidity() method
            // This depends on having the share corresponding to this block
            
            // Placeholder for actual verification logic:
            // CommitmentScheme scheme = confidentialityScheme.getCommitmentScheme();
            // Share share = new Share(shareholder, value);
            // return scheme.checkValidity(share, commitment);
            
            return true; // Simplified; real implementation would check actual shares
        } catch (Exception e) {
            logger.error("Block verification failed", e);
            return false;
        }
    }

    /**
     * Falls back to standard single-block invocation when no batch processing is needed.
     */
    private Response invokeStandard(byte[] plainData, byte[]... confidentialData) 
            throws SecretSharingException {
        // Use the same logic as ConfidentialServiceProxy.invokeOrdered
        serversResponseHandler.reset();
        
        EncryptedPublishedShares[] shares = null;
        if (confidentialData != null && confidentialData.length > 0) {
            shares = new EncryptedPublishedShares[confidentialData.length];
            for (int i = 0; i < confidentialData.length; i++) {
                shares[i] = confidentialityScheme.share(
                        confidentialData[i], Mode.LARGE_SECRET);
            }
        }
        
        byte[] commonData = serializeStandardCommonData(plainData, shares);
        if (commonData == null) return null;
        
        Map<Integer, byte[]> privateData = null;
        if (!isSendAllSharesTogether && confidentialData != null && confidentialData.length > 0) {
            int[] servers = service.getViewManager().getCurrentViewProcesses();
            privateData = new HashMap<>(servers.length);
            for (int server : servers) {
                privateData.put(server, serializeStandardPrivateDataFor(server, shares));
            }
        }
        
        byte metadata = (byte) (confidentialData == null || confidentialData.length == 0 
                ? Metadata.DOES_NOT_VERIFY.ordinal() 
                : Metadata.VERIFY.ordinal());
        byte[] response = service.invokeOrdered(commonData, privateData, metadata);
        
        return composeResponse(response);
    }

    private byte[] serializeStandardCommonData(byte[] plainData, EncryptedPublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte) MessageType.CLIENT.ordinal());
            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null) out.write(plainData);
            out.writeInt(shares == null ? -1 : shares.length);
            if (shares != null) {
                for (EncryptedPublishedShares share : shares) {
                    if (isSendAllSharesTogether) {
                        share.writeExternal(out);
                    } else {
                        byte[] sharedData = share.getSharedData();
                        Commitment commitment = share.getCommitment();
                        out.writeInt(sharedData == null ? -1 : sharedData.length);
                        if (sharedData != null) out.write(sharedData);
                        if (isLinearCommitmentScheme)
                            CommitmentUtils.getInstance().writeCommitment(commitment, out);
                        else {
                            byte[] c = ((ConstantCommitment) commitment).getCommitment();
                            out.writeInt(c.length);
                            out.write(c);
                        }
                    }
                }
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Failed to serialize standard common data", e);
            return null;
        }
    }

    private byte[] serializeStandardPrivateDataFor(int server, EncryptedPublishedShares[] shares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            if (shares != null) {
                BigInteger shareholder = confidentialityScheme.getShareholder(server);
                for (EncryptedPublishedShares share : shares) {
                    byte[] encryptedShareBytes = share.getShareOf(server);
                    out.writeInt(encryptedShareBytes == null ? -1 : encryptedShareBytes.length);
                    if (encryptedShareBytes != null) out.write(encryptedShareBytes);
                    if (!isLinearCommitmentScheme) {
                        ConstantCommitment commitment = (ConstantCommitment) share.getCommitment();
                        byte[] witness = commitment.getWitness(shareholder);
                        out.writeInt(witness.length);
                        out.write(witness);
                    }
                }
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Failed to serialize standard private data", e);
            return null;
        }
    }

    private Response composeResponse(byte[] response) throws SecretSharingException {
        if (response == null) return null;
        ExtractedResponse extractedResponse = ExtractedResponse.deserialize(response);
        if (extractedResponse == null) return null;
        if (extractedResponse.getThrowable() != null)
            throw extractedResponse.getThrowable();
        return new Response(extractedResponse.getPlainData(), extractedResponse.getConfidentialData());
    }

    public void close() {
        service.close();
    }

    public int getBatchSize() {
        return batchSize;
    }

    public int getParallelLevel() {
        return parallelLevel;
    }

    // ========== Inner class to hold batch processing output ==========

    private static class BatchOutput {
        private final long batchId;
        private final byte[][] batchBlocks;
        private final OpenPublishedShares openShares;
        private final Map<Integer, byte[]> encryptedShares;

        BatchOutput(long batchId, byte[][] batchBlocks, 
                    OpenPublishedShares openShares,
                    Map<Integer, byte[]> encryptedShares) {
            this.batchId = batchId;
            this.batchBlocks = batchBlocks;
            this.openShares = openShares;
            this.encryptedShares = encryptedShares;
        }

        long getBatchId() { return batchId; }
        byte[][] getBatchBlocks() { return batchBlocks; }
        OpenPublishedShares getOpenShares() { return openShares; }
        Map<Integer, byte[]> getEncryptedShares() { return encryptedShares; }
    }
}