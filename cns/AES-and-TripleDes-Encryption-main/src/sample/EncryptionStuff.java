package sample;


import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptionStuff {
    @FXML
    private TextField dataTxt;

    @FXML
    private TextField keyTxt;

    @FXML
    private RadioButton AESRBtn;

    @FXML
    private ToggleGroup Encryption;

    @FXML
    private RadioButton DesRBtn;

    @FXML
    private TextArea result;


    private static final String SALT = "ThisIsSalt";

    private static final String algo = "DESede";
    private KeySpec keyspec;
    private SecretKeyFactory skf;
    private static Cipher cipher;
    private byte[] Tkeybytes;
    private String TencryptionAlgo, encryptedDate, decryptedDate, tsk;
    private SecretKey Tsecretkey;


    public static String AESencryption(String data, String aes_Key) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keyspec = new PBEKeySpec(aes_Key.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey sk = factory.generateSecret(keyspec);
            SecretKeySpec secretKeyspec = new SecretKeySpec(sk.getEncoded(), "AES");

            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeyspec, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String AESdecryption(String data, String aes_Key) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keyspec = new PBEKeySpec(aes_Key.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey sk = factory.generateSecret(keyspec);
            SecretKeySpec secretKeyspec = new SecretKeySpec(sk.getEncoded(), "AES");

            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeyspec, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
    public String TDESecnryption() throws Exception {
        byte[] encryptKey = keyTxt.getText().getBytes();
        DESedeKeySpec spec = new DESedeKeySpec (encryptKey);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey theKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        IvParameterSpec IvParameters = new IvParameterSpec(new byte[]{12, 34, 56, 78, 90, 87, 65, 43});
        cipher.init(Cipher.ENCRYPT_MODE, theKey, IvParameters);
        byte[] encrypted = cipher.doFinal(dataTxt.getText().getBytes());
        String txt = Base64.getEncoder().encodeToString(encrypted);
        result.setText(txt);
        return null;
    }
    public String TDESdecrypt() throws Exception{
        byte[] encryptKey = keyTxt.getText().getBytes();
        DESedeKeySpec spec = new DESedeKeySpec (encryptKey);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey theKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        IvParameterSpec IvParameters = new IvParameterSpec(new byte[]{12, 34, 56, 78, 90, 87, 65, 43});
        cipher.init(Cipher.DECRYPT_MODE, theKey, IvParameters);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(dataTxt.getText().getBytes()));
        String dec = new String(original);
        result.setText(dec);
        return null;
    }
    @FXML
    void onActionEncrypt(ActionEvent event) throws Exception {
        if (keyTxt.getText().trim().isEmpty() && dataTxt.getText().trim().isEmpty()) {
            System.out.println("Didnt work");
        } else if (keyTxt.getText().trim().isEmpty()) {
            System.out.println("key is empty");
        } else if (dataTxt.getText().trim().isEmpty()) {
            System.out.println("Data is empty");
        } else {
            if (AESRBtn.isSelected()) {
                result.setText(AESencryption(dataTxt.getText(), keyTxt.getText()));
            } else if (DesRBtn.isSelected()) {
                if (keyTxt.getText().length() <= 23) {
                    System.out.println("Wrong Key size");
                } else {
                    TDESecnryption();
                }
            } else {
                System.out.println("Please select an encryption type");
            }
        }
    }
    @FXML
    void onActionDecrypt(ActionEvent event) throws Exception{
        if (keyTxt.getText().trim().isEmpty() && dataTxt.getText().trim().isEmpty()) {
            System.out.println("Didnt work");
        } else if (keyTxt.getText().trim().isEmpty()) {
            System.out.println("key is empty");
        } else if (dataTxt.getText().trim().isEmpty()) {
            System.out.println("Data is empty");
        } else {
            if (AESRBtn.isSelected()) {
                result.setText(AESdecryption(dataTxt.getText(), keyTxt.getText()));
            } else if (DesRBtn.isSelected()) {
                if (keyTxt.getText().length() <= 23) {
                    System.out.println("Wrong Key size");
                } else {
                    TDESdecrypt();
                }
            } else {
                System.out.println("Please select an encryption type");
            }
        }
    }
}