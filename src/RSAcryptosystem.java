
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

public class RSAcryptosystem {
    private int keyLength;
    private BigInteger p;
    private BigInteger q;
    private BigInteger e;
    private BigInteger d;
    private BigInteger n;
    private ArrayList<byte[]> resCiphering;
    private ReaderWriter forReadwrite;
    private static final char[] hexArray = "0123456789abcdef".toCharArray();

    RSAcryptosystem(int lght) throws Exception {
        boolean correct = false;
        if(lght == 512 || lght == 1024 || lght == 2048){
            keyLength = lght;
            correct = true;
        }
        if(!correct){
            throw new Exception("Size of key must be 512, 1024 or 2048 bits");
        }
    }

    public void generateKey(boolean byPassword) throws NoSuchAlgorithmException {
        Random rand = new Random();
        int seed;
        if(byPassword){
            seed = generateByPassword();
        }
        else {
            seed = 5;
        }
            while (true) {
                BigInteger p = new BigInteger(keyLength, seed, rand);
                BigInteger q = new BigInteger(keyLength, seed, rand);
                if (testMillerRabin(p, 1) && testMillerRabin(q, 1)) {
                    this.p = p;
                    this.q = q;
                    break;
                }
            }

        this.n = p.multiply(q);
        BigInteger FI = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e;

        while (true) {
            do {
                e = new BigInteger(keyLength*2, rand);
            }
            while (e.compareTo(FI) >= 0);
            BigInteger gcd = e.gcd(FI);
            if(gcd.compareTo(BigInteger.ONE) == 0){
                break;
            }
        }
        this.d = algorythmEuclid(e, FI);
        this.e = e;
    }

    private int generateByPassword() throws NoSuchAlgorithmException {
        Scanner cs = new Scanner(System.in);
        System.out.println("Please, input password");
        String pass = cs.nextLine();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pass.getBytes());
        byte[] res = md.digest();
        ByteBuffer wrapped = ByteBuffer.wrap(res);
        return wrapped.getInt();
    }

    private boolean testMillerRabin(BigInteger n, int k){
        BigInteger TWO = BigInteger.valueOf(2);
        BigInteger THREE = BigInteger.valueOf(3);

        if(n.equals(TWO) || n.equals(THREE)){
            return true;
        }

        if(n.compareTo(TWO) < 0 || n.mod(TWO).equals(BigInteger.ZERO)){
            return false;
        }

        BigInteger t = n.subtract(BigInteger.ONE);
        int s = 0;
        BigInteger n_2 = n.subtract(BigInteger.valueOf(2));
        while(t.remainder(TWO).equals(BigInteger.ZERO)){
            t = t.divide(TWO);
            s += 1;
        }

        for(int i = 0; i < k; i++){

            SecureRandom random = new SecureRandom();
            byte[] _a = new byte [n.toByteArray().length];
            BigInteger a;
            do{
                random.nextBytes(_a);
                a = new BigInteger(_a);
            }
            while(a.compareTo(TWO) < 0 || a.compareTo(n_2) >= 0);

            BigInteger x = a.modPow(t, n);
            BigInteger n_1 = n.subtract(BigInteger.valueOf(1));

            if(x.equals(BigInteger.ONE) || x.equals(n_1)){
                continue;
            }

            for(int r = 1; r < s; r++){
                x = x.modPow(TWO, n);
                if(x.equals(BigInteger.ONE)){
                    return false;
                }
                if(x.equals(n_1)){
                    break;
                }
            }
            if(!x.equals(n_1)){
                return false;
            }
        }
        return true;
    }

    private BigInteger algorythmEuclid(BigInteger n, BigInteger p){
        BigInteger Rminus = p;
        BigInteger Rzero = n;
        BigInteger Yminus = BigInteger.ZERO;
        BigInteger Yzero = BigInteger.ONE;
        BigInteger q;
        BigInteger Rnow;
        BigInteger Ynow;
        BigInteger a;
        while(true){
            q = Rminus.divide(Rzero);
            Rnow = Rminus.subtract(Rzero.multiply(q));
            while(Rnow.compareTo(BigInteger.ZERO) < 0){
                Rnow = Rnow.add(p);
            }
            if(Rnow.equals(BigInteger.ZERO)){
                a = Yzero;
                break;
            }
            Ynow = Yminus.subtract(Yzero.multiply(q));
            while(Ynow.compareTo(BigInteger.ZERO) < 0){
                Ynow = Ynow.add(p);
            }
            Rminus = Rzero;
            Rzero = Rnow;
            Yminus = Yzero;
            Yzero = Ynow;

        }
        return a;
    }

    private void createDigitalSignature(String filename) throws FileNotFoundException {
        Scanner scan = new Scanner(new File(filename));
        String content = "";
        while(scan.hasNext()){
            content = scan.nextLine();
        }

        StringBuilder sb = new StringBuilder();
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(content.getBytes());
            byte[] byteData = md.digest();
            sb.append(bytesToHex(byteData));
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        FileWriter fr;
        try{
            fr = new FileWriter(new File(filename), true);
            fr.write(sb.toString());
            fr.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    private String bytesToHex(byte[] bytes){
        char[] hexChars = new char[bytes.length*2];
        for(int i = 0; i < bytes.length; i++){
            int v = bytes[i] & 0xFF;
            hexChars[i*2] = hexArray[v >>> 4];
            hexChars[i*2+1] = hexArray[v & 0x0F];
        }
        return String.valueOf(hexChars);
    }

    public void encryption(String filename, boolean param) throws IOException {
        if(param){
         createDigitalSignature(filename);
        }
        ArrayList<byte[]> plaintext;
        forReadwrite = new ReaderWriter(keyLength);
        plaintext = forReadwrite.read(filename);
        ArrayList<byte[]> cifertext = new ArrayList<>();

        for(int i = 0; i < plaintext.size(); i++ ){
            BigInteger block = new BigInteger(plaintext.get(i));
            BigInteger ciferBlock = block.modPow(e,n);
            cifertext.add(ciferBlock.toByteArray());

        }
        resCiphering = cifertext;
        forReadwrite.write(cifertext, true);
    }

    void decryption(String filename) throws IOException {

        ArrayList<byte[]> secretext = resCiphering;
        ArrayList<byte[]> restext = new ArrayList<>();
        for(int i = 0; i < secretext.size(); i++){
            BigInteger block = new BigInteger(secretext.get(i));
            BigInteger deciferBlock = block.modPow(d,n);
            restext.add(deciferBlock.toByteArray());
        }
        forReadwrite.write(restext, false);
    }
    public BigInteger getE(){return e;}
    public BigInteger getN(){return n;}
    public BigInteger getD(){return d;}
    public BigInteger getP(){return p;}
    public BigInteger getQ(){return q;}


































}

