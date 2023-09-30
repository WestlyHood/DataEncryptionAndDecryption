import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class DataEncryptAndDecrypt extends JFrame {
  private JTextArea inputTextArea, outputTextArea;
  private JButton encryptButton, decryptButton;
  private KeyPair rsaKeyPair;
  private SecretKey aesKey;
  private byte[] encryptedData;
  private byte[] encryptedAesKey;

  public DataEncryptAndDecrypt() {
    setTitle("Encryption/Decryption Tool");
    setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    setSize(400, 300);
    setLocationRelativeTo(null);

    // Initialize GUI components
    inputTextArea = new JTextArea(5, 30);
    outputTextArea = new JTextArea(5, 30);
    encryptButton = new JButton("Encrypt");
    decryptButton = new JButton("Decrypt");

    // Layout components
    JPanel panel = new JPanel();
    panel.setLayout(new GridLayout(4, 2));
    panel.add(new JLabel("Enter Text:"));
    panel.add(new JLabel("Result:"));
    panel.add(new JScrollPane(inputTextArea));
    panel.add(new JScrollPane(outputTextArea));
    panel.add(encryptButton);
    panel.add(decryptButton);

    // Add action listeners
    encryptButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        // Step 1: Generate RSA Key Pair
        generateKeys();

        // Step 2: Encrypt data using AES
        encryptData();
      }
    });

    decryptButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        // Step 4: Decrypt AES key using RSA
        decryptAesKey();

        // Step 5: Decrypt AES Data
        decryptData();
      }
    });

    // Set up the layout
    setLayout(new BorderLayout());
    add(panel, BorderLayout.CENTER);

    setVisible(true);
  }

  public void generateKeys() {
    try {
      // Generate RSA Key Pair
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      keyGen.initialize(2048);
      rsaKeyPair = keyGen.generateKeyPair();

      // Generate AES Key
      KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
      aesKeyGen.init(256); // You can adjust the key size as needed
      aesKey = aesKeyGen.generateKey();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void encryptData() {
    try {
      // Step 2: Encrypt data using AES
      // Get the input data
      String inputData = inputTextArea.getText();

      // Initialize the cipher
      Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

      // Encrypt the data
      encryptedData = aesCipher.doFinal(inputData.getBytes());

      // Step 3: Encrypt AES key using RSA
      Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
      encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

      // Display the encrypted data and encrypted AES key
      outputTextArea.setText("Encrypted Data:\n" + Base64.getEncoder().encodeToString(encryptedData) +
          "\n\nEncrypted AES Key:\n" + Base64.getEncoder().encodeToString(encryptedAesKey));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void decryptAesKey() {
    try {
      // Step 4: Decrypt AES key using RSA
      Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
      byte[] decryptedAesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
      aesKey = new SecretKeySpec(decryptedAes
