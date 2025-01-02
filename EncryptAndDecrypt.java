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
    private byte[] iv;

    public DataEncryptAndDecrypt() {
        setTitle("Encryption/Decryption Tool");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 400);
        setLocationRelativeTo(null);

        inputTextArea = new JTextArea(5, 30);
        outputTextArea = new JTextArea(5, 30);
        encryptTextButton = new JButton("Encrypt Text");
        encryptFileButton = new JButton("Encrypt File");
        decryptTextButton = new JButton("Decrypt Text");
        decryptFileButton = new JButton("Decrypt File");

        JPanel panel = new JPanel(new GridLayout(5, 2, 10, 10));
        panel.add(new JLabel("Input Text/File:"));
        panel.add(new JLabel("Output:"));
        panel.add(new JScrollPane(inputTextArea));
        panel.add(new JScrollPane(outputTextArea));
        panel.add(encryptTextButton);
        panel.add(encryptFileButton);
        panel.add(decryptTextButton);
        panel.add(decryptFileButton);

        setLayout(new BorderLayout());
        add(panel, BorderLayout.CENTER);

        encryptTextButton.addActionListener(e -> encryptText());
        encryptFileButton.addActionListener(e -> chooseFileForEncryption());
        decryptTextButton.addActionListener(e -> decryptText());
        decryptFileButton.addActionListener(e -> chooseFileForDecryption());

        setVisible(true);
    }

    private void generateKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            rsaKeyPair = keyGen.generateKeyPair();

            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
            aesKeyGen.init(256);
            aesKey = aesKeyGen.generateKey();
        } catch (Exception e) {
            showError("Error generating keys: " + e.getMessage());
        }
    }

    private void encryptText() {
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
            showError("Error during text encryption: " + e.getMessage());
        }
    }

    private void chooseFileForEncryption() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Choose a file for encryption");
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            encryptFile(fileChooser.getSelectedFile());
        }
    }

    private void encryptFile(File inputFile) {
        try {
            generateKeys();

            SecureRandom random = new SecureRandom();
            iv = new byte[16];
            random.nextBytes(iv);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));

            File outputFile = new File(inputFile.getParent(), "encrypted_" + inputFile.getName());

            try (CipherInputStream cis = new CipherInputStream(new FileInputStream(inputFile), aesCipher);
                 FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
            }

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
            encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

            outputTextArea.setText("File Encrypted Successfully.\nEncrypted AES Key:\n" +
                    Base64.getEncoder().encodeToString(encryptedAesKey) +
                    "\nInitialization Vector (IV):\n" + Base64.getEncoder().encodeToString(iv));
        } catch (Exception e) {
            showError("Error during file encryption: " + e.getMessage());
        }
    }

    private void decryptText() {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
            byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedAesKey, "AES"), new IvParameterSpec(iv));

            byte[] decryptedBytes = aesCipher.doFinal(encryptedData);

            outputTextArea.setText("Decrypted Text:\n" + new String(decryptedBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            showError("Error during text decryption: " + e.getMessage());
        }
    }

    private void chooseFileForDecryption() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Choose a file for decryption");
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            decryptFile(fileChooser.getSelectedFile());
        }
    }

    private void decryptFile(File inputFile) {
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
            byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedAesKey, "AES"), new IvParameterSpec(iv));

            File outputFile = new File(inputFile.getParent(), "decrypted_" + inputFile.getName());

            try (CipherInputStream cis = new CipherInputStream(new FileInputStream(inputFile), aesCipher);
                 FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
            }

            outputTextArea.setText("File Decrypted Successfully.");
        } catch (Exception e) {
            showError("Error during file decryption: " + e.getMessage());
        }
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(DataEncryptAndDecrypt::new);
    }
}
