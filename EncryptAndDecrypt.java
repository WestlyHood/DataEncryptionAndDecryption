import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.util.Base64;

public class DataEncryptAndDecrypt extends JFrame {
    private JTextArea inputTextArea, outputTextArea;
    private JButton encryptTextButton, encryptFileButton, decryptTextButton, decryptFileButton;
    private KeyPair rsaKeyPair;
    private SecretKey aesKey;
    private byte[] encryptedData;
    private byte[] encryptedAesKey;
    private byte[] decryptedAesKey;
    private byte[] iv;

    public DataEncryptAndDecrypt() {
        setTitle("Encryption/Decryption Tool");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(400, 300);
        setLocationRelativeTo(null);

        inputTextArea = new JTextArea(5, 30);
        outputTextArea = new JTextArea(5, 30);
        encryptTextButton = new JButton("Encrypt Text");
        encryptFileButton = new JButton("Encrypt File");
        decryptTextButton = new JButton("Decrypt Text");
        decryptFileButton = new JButton("Decrypt File");

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(5, 2));
        panel.add(new JLabel("Enter Text/File:"));
        panel.add(new JLabel("Result:"));
        panel.add(new JScrollPane(inputTextArea));
        panel.add(new JScrollPane(outputTextArea));
        panel.add(encryptTextButton);
        panel.add(encryptFileButton);
        panel.add(decryptTextButton);
        panel.add(decryptFileButton);

        encryptTextButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                encryptText();
            }
        });

        encryptFileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Choose a file for encryption");
                int result = fileChooser.showOpenDialog(DataEncryptAndDecrypt.this);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    encryptFile(selectedFile);
                }
            }
        });

        decryptTextButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                decryptText();
            }
        });

        decryptFileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Choose a file for decryption");
                int result = fileChooser.showOpenDialog(DataEncryptAndDecrypt.this);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    decryptFile(selectedFile);
                }
            }
        });

        setLayout(new BorderLayout());
        add(panel, BorderLayout.CENTER);

        setVisible(true);
    }

    public void generateKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            rsaKeyPair = keyGen.generateKeyPair();

            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
            aesKeyGen.init(256);
            aesKey = aesKeyGen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void encryptText() {
        try {
            generateKeys();

            SecureRandom random = new SecureRandom();
            iv = new byte[16];
            random.nextBytes(iv);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

            String inputData = inputTextArea.getText();
            encryptedData = aesCipher.doFinal(inputData.getBytes(StandardCharsets.UTF_8));

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
            encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

            outputTextArea.setText("Encrypted Text:\n" + Base64.getEncoder().encodeToString(encryptedData) +
                    "\n\nEncrypted AES Key:\n" + Base64.getEncoder().encodeToString(encryptedAesKey) +
                    "\n\nInitialization Vector (IV):\n" + Base64.getEncoder().encodeToString(iv));
        } catch (Exception e) {
            e.printStackTrace();
            outputTextArea.setText("Error during text encryption: " + e.getMessage());
        }
    }

    public void encryptFile(File inputFile) {
        try {
            generateKeys();

            SecureRandom random = new SecureRandom();
            iv = new byte[16];
            random.nextBytes(iv);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

            File outputFile = new File(inputFile.getParent(), "encrypted_" + inputFile.getName());

            // Encrypt file
            CipherInputStream cis = new CipherInputStream(new FileInputStream(inputFile), aesCipher);
            Files.copy(cis, outputFile.toPath());
            cis.close();

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
            encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

            outputTextArea.setText("File Encrypted Successfully:\n" +
                    "Encrypted AES Key: " + Base64.getEncoder().encodeToString(encryptedAesKey) +
                    "\nInitialization Vector (IV): " + Base64.getEncoder().encodeToString(iv));
        } catch (Exception e) {
            e.printStackTrace();
            outputTextArea.setText("Error during file encryption: " + e.getMessage());
        }
    }

    public void decryptText() {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
            decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedAesKey, "AES"), new IvParameterSpec(iv));

            byte[] decryptedBytes = aesCipher.doFinal(encryptedData);

            outputTextArea.setText("Decrypted Text:\n" + new String(decryptedBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
            outputTextArea.setText("Error during text decryption: " + e.getMessage());
        }
    }

    public void decryptFile(File inputFile) {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
            decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedAesKey, "AES"), new IvParameterSpec(iv));

            File outputFile = new File(inputFile.getParent(), "decrypted_" + inputFile.getName());

            // Decrypt file
            CipherInputStream cis = new CipherInputStream(new FileInputStream(inputFile), aesCipher);
            Files.copy(cis, outputFile.toPath());
            cis.close();

            outputTextArea.setText("File Decrypted Successfully");
        } catch (Exception e) {
            e.printStackTrace();
            outputTextArea.setText("Error during file decryption: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new DataEncryptAndDecrypt();
            }
        });
    }
}
