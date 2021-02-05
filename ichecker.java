/**
 * Main class
 **/
public class ichecker {
    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "createCert":
                new CreateCert(args[2], args[4]);
                break;
            case "createReg":
                new CreateReg(args[2], args[4], args[6], args[8], args[10]);
                break;
            case "check":
                new Check(args[2], args[4], args[6], args[8], args[10]);
                break;
        }
    }
}