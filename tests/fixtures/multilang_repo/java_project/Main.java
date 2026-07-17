import java.util.List;
import java.util.ArrayList;

public class Main {
    public static String processInput(String input) {
        return validateData(input);
    }

    private static String validateData(String data) {
        return data != null ? data.trim() : "";
    }

    public static void main(String[] args) {
        processInput("test");
    }
}
