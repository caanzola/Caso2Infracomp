import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Security;
import java.security.cert.*;

import org.bouncycastle.cert.*;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.jcajce.*;

public class Cliente 
{

	private final static String CERTIFICADO = "CERTCLNT";
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
				if(fromUser != null && fromUser.equals(CERTIFICADO))
				{
					escritor.print(CERTIFICADO);
					java.security.cert.X509Certificate cert = certificado();
					byte[] mybyte = cert.getEncoded();
					socket.getOutputStream().write(mybyte);
					socket.getOutputStream().flush();
					
				}
				
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

	private static X509Certificate certificado() 
	{
		X509Certificate certificado = null;
		try
		{
		Security.addProvider(new BouncyCastleProvider());
		X509v3CertificateBuilder x = new 
		System.out.println(certificado.getPublicKey());
		}
		catch (Exception e)
		{
			System.out.println("Error en generación de certificado");
		}
		return certificado;
	}

}
