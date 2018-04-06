import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;

public class Cliente 
{

	//private final static String IP = ;
	private final static int PUERTO = 8080;  
	
	public static void main(String[] args) 
	{
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		try 
		{

			socket = new Socket(InetAddress.getLocalHost().getHostAddress(), PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			
			String fromServer;
			String fromUser;
			boolean ejecutar = true;
			while (ejecutar) 
			{
				System.out.print("Escriba el mensaje para enviar:");
				fromUser = stdIn.readLine();
				escritor.println(fromUser);
				if ((fromServer = lector.readLine()) != null) 
				{
					System.out.println("Servidor: " + fromServer);
				}
			}
			escritor.close();
			lector.close();
			// cierre el socket y la entrada estándar
			socket.close();
		}
		catch(Exception e)
		{
			System.out.println("Error " + e.getMessage());
			System.exit(1);
		}
	}

}
