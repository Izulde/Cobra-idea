package confidential.client;

import vss.commitment.Commitment;
import vss.polynomial.Polynomial;

import java.io.*;
import java.util.Arrays;

/**
 * Represents a batch message containing multiple blocks aggregated together
 * with a single polynomial and commitment.
 */
public class BatchMessage implements Externalizable {
    private static final long serialVersionUID = 1L;
    
    private long batchId;
    private byte[][] batchBlocks;
    private Polynomial polynomial;
    private Commitment commitment;

    public BatchMessage() {}

    public BatchMessage(long batchId, byte[][] batchBlocks, Polynomial polynomial, Commitment commitment) {
        this.batchId = batchId;
        this.batchBlocks = batchBlocks;
        this.polynomial = polynomial;
        this.commitment = commitment;
    }

    public long getBatchId() {
        return batchId;
    }

    public byte[][] getBatchBlocks() {
        return batchBlocks;
    }

    public Polynomial getPolynomial() {
        return polynomial;
    }

    public Commitment getCommitment() {
        return commitment;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeLong(batchId);
        out.writeInt(batchBlocks.length);
        for (byte[] block : batchBlocks) {
            out.writeInt(block.length);
            out.write(block);
        }
        // Serialize polynomial coefficients
        java.math.BigInteger[] coefficients = polynomial.getCoefficients();
        out.writeInt(coefficients.length);
        for (java.math.BigInteger coeff : coefficients) {
            byte[] coeffBytes = coeff.toByteArray();
            out.writeInt(coeffBytes.length);
            out.write(coeffBytes);
        }
        // Serialize field
        // Note: Polynomial doesn't expose field getter, so we handle this externally
        // Commitment is written via CommitmentUtils in the proxy
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        batchId = in.readLong();
        int numBlocks = in.readInt();
        batchBlocks = new byte[numBlocks][];
        for (int i = 0; i < numBlocks; i++) {
            int blockLen = in.readInt();
            batchBlocks[i] = new byte[blockLen];
            in.readFully(batchBlocks[i]);
        }
        int numCoeffs = in.readInt();
        java.math.BigInteger[] coefficients = new java.math.BigInteger[numCoeffs];
        for (int i = 0; i < numCoeffs; i++) {
            int coeffLen = in.readInt();
            byte[] coeffBytes = new byte[coeffLen];
            in.readFully(coeffBytes);
            coefficients[i] = new java.math.BigInteger(coeffBytes);
        }
        // Polynomial and commitment need special deserialization handled externally
    }

    @Override
    public String toString() {
        return "BatchMessage{" +
                "batchId=" + batchId +
                ", batchBlocks=" + Arrays.deepToString(batchBlocks) +
                '}';
    }
}