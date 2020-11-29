import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.io.*;
public class Server {
    static final String path = "C:\\Users\\Muhammad\\Desktop\\TestingProject\\Sources";

    public static boolean find_file(String name) {
        File f = new File(path);
        String names[] = f.list();
        for (String k : names) {
            if (k.equals(name))
                return true;
        }
        return false;
    }

    public static void main(String[] args) {
        try (ServerSocket listener = new ServerSocket(11111)) {
            String message=new String();
            String to_return=new String();
            System.out.println("The date server is running...");
            while (true) {
                try (Socket socket = listener.accept()) { // accept is a blocking call
                    //read the request from client
                    // get the input stream from the connected socket
                    InputStream inputStream = socket.getInputStream();
                    // create a DataInputStream so we can read data from it.
                    ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

                    // read the list of messages from the socket
                    Request request = (Request) objectInputStream.readObject();
                    String name =request.getName();
                    boolean isEdited =request.isEdited();
                    String text =request.getText();
                    System.out.println(request);

                    if (isEdited) { //need to modify the file
                            try {
                                FileWriter fileWriter = new FileWriter(path + "\\" + name);
                                PrintWriter printWriter = new PrintWriter(fileWriter);
                                printWriter.print(text);
                                printWriter.close();
                                message = "file edited successfully";
                                to_return=text;
                            } catch (Exception e) {
                                System.out.println(e.getCause());
                            }
                        }

                    else { // read the file text and return it to
                        if(find_file(name)){
                            File to_read = new File(path+"\\"+name);
                            Scanner my_scanner = new Scanner(to_read);

                            while(my_scanner.hasNextLine()){
                                to_return += my_scanner.nextLine();
                            }
                            my_scanner.close();
                            message = "file founded";
                        }

                        else {
                            message = "file does not existed";
                        }
                    }
//                    Response response = new Response(text,message);
//                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
//                    out.print(response);
                }
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
