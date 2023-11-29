package idea_cipher;

public class IdeaCipherException extends  Throwable{
    private final String message;

    IdeaCipherException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
