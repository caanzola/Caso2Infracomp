import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class ClientePrueba {

	public ClientePrueba() throws UnknownHostException, IOException 
	{
			
			Socket socket = new Socket(InetAddress.getLocalHost().getHostName(), 8080);
			PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
			BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));

			escritor.println("HOLA");
			System.out.println(lector.readLine());
		
		
	}

}
