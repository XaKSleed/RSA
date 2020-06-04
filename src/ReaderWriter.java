import java.io.*;
import java.util.ArrayList;

public class ReaderWriter {
    private ArrayList<byte[]> plaintext = new ArrayList<>();
    private int countOfBlock;
    private int keySize;
    private int additionBits;
    private byte[] buffer;
    private boolean isImg;

    ReaderWriter(int size){

        keySize = size;
    }


    public ArrayList<byte[]> read (String filename) throws IOException {

        FileInputStream fin = new FileInputStream(filename);
        buffer = new byte[fin.available()];
        fin.read(buffer, 0, fin.available());
        fin.close();

        int blockSize = keySize/8;
        countOfBlock = buffer.length / blockSize;
        additionBits = buffer.length % blockSize;

        byte[] tmp = new byte[blockSize];
        for(int i = 0; i < countOfBlock; i++){
            tmp = new byte[blockSize];
            for(int j = 0; j < blockSize; j++){
                tmp[j] = buffer[j + i * blockSize];
            }
            plaintext.add(i, tmp);
        }

        if (buffer.length % blockSize != 0){
            tmp = new byte[blockSize];
            for(int i = blockSize * countOfBlock; i < buffer.length; i++) {
                tmp[i % blockSize] = buffer[i];
            }

            for(int i = buffer.length % blockSize; i < tmp.length; i++){
                tmp[i] = 0;
            }
        }
        plaintext.add(tmp);
        return plaintext;
    }

    public void write(ArrayList<byte[]> writeData, boolean param) throws IOException {

        String filename = "";

            if (param) {
                filename = "Encrypted.txt";

            }
            if (!param) {
                filename = "Decrypted.txt";
            }
            File file = new File(filename);

            PrintWriter out = new PrintWriter(file.getAbsoluteFile());

            for (int i = 0; i < writeData.size(); i++) {
                for (int j = 0; j < writeData.get(i).length; j++) {
                    if (i == writeData.size() - 1 & j == additionBits) {
                        break;
                    }
                    out.print((char) (writeData.get(i)[j] & 0xFF));
                }
            }

            out.close();

    }

}



