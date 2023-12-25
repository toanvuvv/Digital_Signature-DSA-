package org.example;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;
import java.util.Objects;

public class Main extends Application {

    public AnchorPane mainForm;

    @Override
    public void start(Stage stage) throws Exception {
        Scene scene = new Scene(FXMLLoader.load(Objects.requireNonNull(getClass().getResource("/DSAForm.fxml"))));
        stage.setScene(scene);
        stage.setTitle("Crypto");
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }


    @FXML
    public void loadDSAForm(ActionEvent actionEvent) throws Exception {
        DSAController dsaController = new DSAController();
        dsaController.start((Stage) mainForm.getScene().getWindow());
    }
}
