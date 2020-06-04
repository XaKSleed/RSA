
public class Main {

    public static void main(String[] args) throws Exception {

        RSAcryptosystem sys1 = new RSAcryptosystem(512);
        sys1.generateKey(false);
        System.out.println("p = " + sys1.getP());
        System.out.println("q = " + sys1.getQ());
        System.out.println("Open key: " + "(" + "e = " + sys1.getE() + ", " + "n = " + sys1.getN() + ")");
        System.out.println("Secret key: " + "(" + "d = " + sys1.getD() + ", " + "n = " + sys1.getN() + ")");
        sys1.encryption("Message.txt", true);
        sys1.decryption("Message.txt");

    }
}
