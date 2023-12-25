package org.example;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class DSAController extends Application {
    public AnchorPane dsaForm;
    public TextField privateKeyField;
    public TextField publicKeyField;
    public TextField pField;
    public TextField qField;
    public TextField gField;
    public Button generateButton;
    public Button signButton;
    public Button verifyButton;
    public TextArea messageField;
    public TextArea signatureField;

    private byte[] message;
    private boolean messageFromFile = false;

    private final DSA dsa;

    {
        dsa = new DSA(new SHA1());
    }

    @Override
    public void start(Stage stage) throws Exception {
        Scene scene = new Scene(FXMLLoader.load(Objects.requireNonNull(getClass().getResource("/DSAForm.fxml"))));
        stage.setScene(scene);
    }


    public void generateKeys(ActionEvent actionEvent) {
        dsa.generateKeys();
        privateKeyField.setText(Convert.convertByteArrayToHexString(dsa.getPrivateKey()));
        publicKeyField.setText(Convert.convertByteArrayToHexString(dsa.getPublicKey()));
        pField.setText(Convert.convertByteArrayToHexString(dsa.getP()));
        qField.setText(Convert.convertByteArrayToHexString(dsa.getQ()));
        gField.setText(Convert.convertByteArrayToHexString(dsa.getG()));
    }

    public void sign(ActionEvent actionEvent) {
        try {
            if (!messageFromFile) {
                message = messageField.getText().getBytes(StandardCharsets.UTF_8);
            }
            byte[][] signature = dsa.sign(message);
            signatureField.setText(Convert.convertByteArrayToHexString(signature[0]) + '\n'
                    + Convert.convertByteArrayToHexString(signature[1]));
        } catch (Exception e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void verify(ActionEvent actionEvent) {
        String[] signatureStr = signatureField.getText().split("\n");
        byte[][] signature = new byte[][] {
                Convert.convertHexStringToByteArray(signatureStr[0]),
                Convert.convertHexStringToByteArray(signatureStr[1])
        };
        try {
            if (!messageFromFile) {
                message = messageField.getText().getBytes(StandardCharsets.UTF_8);
            }
            String result = (dsa.verify(message, signature))
                    ? "Valid" : "Invalid";
            Dialog.display("Result", result);
        } catch (Exception e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void loadMessageFromFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileInputStream fs = new FileInputStream(fc.showOpenDialog(dsaForm.getScene().getWindow()).getPath())) {
            message = fs.readAllBytes();
            messageField.setText(new String(message, StandardCharsets.UTF_8));
            messageField.setDisable(true);
            messageFromFile = true;
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void saveMessageToFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileOutputStream fs = new FileOutputStream(fc.showSaveDialog(dsaForm.getScene().getWindow()).getPath())) {
            if (messageFromFile) {
                fs.write(message);
            } else {
                fs.write(messageField.getText().getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void loadSignatureFromFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileInputStream fs = new FileInputStream(fc.showOpenDialog(dsaForm.getScene().getWindow()).getPath())) {
            byte[][] signature = new byte[2][];
            byte[] input = fs.readAllBytes();
            for (int i = 0; i < input.length; ++i) {
                if (input[i] == '\n') {
                    signature[0] = new byte[i];
                    signature[1] = new byte[input.length - (i+1)];
                    System.arraycopy(input, 0, signature[0], 0, i);
                    System.arraycopy(input, i+1, signature[1], 0, input.length - (i+1));
                    break;
                }
            }
            signatureField.setText(Convert.convertByteArrayToHexString(signature[0]) + '\n'
                + Convert.convertByteArrayToHexString(signature[1]));
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }

    public void saveSignatureToFile(ActionEvent actionEvent) {
        FileChooser fc = new FileChooser();
        try (FileOutputStream fs = new FileOutputStream(fc.showSaveDialog(dsaForm.getScene().getWindow()).getPath())) {
            String[] signature = signatureField.getText().split("\n");
            fs.write(Convert.convertHexStringToByteArray(signature[0]));
            fs.write('\n');
            fs.write(Convert.convertHexStringToByteArray(signature[1]));
        } catch (IOException e) {
            Dialog.display("Error", e.getMessage());
        }
    }
}
