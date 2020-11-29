import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class Client {
    public static void main(String args[]){
        try {
            Socket socket = new Socket("localhost", 11111);
            Request request = new Request("hasan.txt",true,"modified text from client");

            // get the output stream from the socket.
            OutputStream outputStream = socket.getOutputStream();
            // create an object output stream from the output stream so we can send an object through it
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            objectOutputStream.writeObject(request);
//            Scanner in = new Scanner(socket.getInputStream());
//            Response clientResponse = new Response(in.nextLine(),in.next());
//            System.out.println(clientResponse);
        } catch (IOException e) {
            System.out.println(e.getCause());
        }

    }

    }
