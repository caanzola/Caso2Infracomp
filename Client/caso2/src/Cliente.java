import java.io.BufferedReader;
import  org.apache.poi.hssf.usermodel.HSSFSheet;
import  org.apache.poi.hssf.usermodel.HSSFWorkbook;
import  org.apache.poi.hssf.usermodel.HSSFRow;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Cliente 
{
	private final static String ALGORITMO_ASIMETRICO="RSA";
	private final static String ALGORITMO_SIMETRICO="AES";
	private final static String ALGORITMO_HMAC="HMACSHA1";
	private final static String PADDING="AES/ECB/PKCS5Padding";
	private final static String POSICION ="41 24.2028, 2 10.4418"; 
	private static SecretKey lls;
	private static PrivateKey privateKey;
	private static PublicKey publicKey;
	private static PublicKey publicKeySer;
	private static byte[] llaveSimetrica;
	private static Long startTime2;
	private static Long totalTimeActualizacion;
	private static Long totalTimeLlaveSimetrica;
	
	public Long darTActualizacion(){
		return totalTimeActualizacion;
	}
	
	public Long darTLlaveS(){
		return totalTimeLlaveSimetrica;
	}

	public Cliente() throws Exception 
	{
			
		

        
			Socket socket = new Socket(InetAddress.getLocalHost().getHostName(), 8080);
//		    Socket socket = new Socket("157.253.239.29", 8080);
			PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
			BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));

			escritor.println("HOLA");
			System.out.println(lector.readLine());
			
			escritor.println("ALGORITMOS:AES:RSA:HMACSHA1");
			System.out.println(lector.readLine());
			
			escritor.println("CERTCLNT");
			java.security.cert.X509Certificate cert = certificado();
			byte[] mybyte = cert.getEncoded();
			socket.getOutputStream().write(mybyte);
			socket.getOutputStream().flush();
			System.out.println(lector.readLine());
			System.out.println("Servidor: " +lector.readLine());
		
			try
			{
				// RECIBIR Y VERIFICAR EL CERTIFICADO QUE ENVIA EL SERVIDOR
				byte[] certificado = new byte[1024];
				socket.getInputStream().read(certificado);
				X509Certificate certSer = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificado));
				publicKeySer = certSer.getPublicKey();
				certSer.verify(publicKeySer);
				escritor.println("ESTADO:OK");
			}
			catch (Exception e) 
			{
				e.printStackTrace();
				escritor.println("ESTADO:ERROR");
			}
			
			Long startTime = System.currentTimeMillis();
			String fromServer = lector.readLine();
;			System.out.println("Servidor: " + fromServer);
			String llaveSimetricaCifradaHexa = fromServer.split(":")[1];
			
			// DESCIFRAR LA LLAVE SIMETRICA
			llaveSimetrica = descifrarLlaveSimetrica(llaveSimetricaCifradaHexa);
			// ENVIAR LAS COORDENADAS CIFRADAS
			enviarCoordenadasCifradas(escritor, startTime);
			
			//ENVIAR EL CODIGO DE INTEGRIDAD
			enviarCodigoDeIntegridad(escritor);
			
			fromServer = lector.readLine();
			Long endtTime2 = System.currentTimeMillis();
			totalTimeActualizacion = endtTime2-startTime2;
			System.out.println("Tiempo total de respuesta a una actualización: "+ totalTimeActualizacion+" milisegundos");
			if(fromServer.equals("ESTADO:OK"))
			{								
				System.out.println("FIN DE LA COMUNICACION");
			}
			else
			{
				System.out.println("HUBO UN ERROR");
			}
			

			escritor.close();
			lector.close();
			socket.close();
	}
	
	private static void enviarCodigoDeIntegridad(PrintWriter escritor) throws Exception 
	{
		Cipher cipher2 = Cipher.getInstance(ALGORITMO_ASIMETRICO);
		cipher2.init(Cipher.ENCRYPT_MODE, publicKeySer);
		
		Mac mac = Mac.getInstance(ALGORITMO_HMAC);
		SecretKeySpec keySpec2 = new SecretKeySpec(llaveSimetrica, ALGORITMO_HMAC);
		mac.init(keySpec2);
		byte[] parcial = mac.doFinal(POSICION.getBytes());
		String mandar= Hex.toHexString(cipher2.doFinal(parcial));
		
		escritor.println("ACT2:"+mandar);
	}

	private static void enviarCoordenadasCifradas(PrintWriter escritor, Long startTime) throws Exception 
	{
		Cipher cipher1 = Cipher.getInstance(ALGORITMO_SIMETRICO);
		SecretKeySpec keySpec = new SecretKeySpec(llaveSimetrica, ALGORITMO_SIMETRICO);
		Long endTime = System.currentTimeMillis();
		totalTimeLlaveSimetrica = endTime-startTime;
		System.out.println("Tiempo para obtener la llave simetrica: "+totalTimeLlaveSimetrica+" milisegundos");
		cipher1.init(Cipher.ENCRYPT_MODE, keySpec);

		String posicion="41 24.2028, 2 10.4418";
		String ACT1 = "ACT1:"+Hex.toHexString(cipher1.doFinal((posicion).getBytes()));
		startTime2 = System.currentTimeMillis();
		escritor.println(ACT1);
	}

	private static byte[] descifrarLlaveSimetrica(String pLlaveCifrada) throws Exception
	{
		Cipher cipher = Cipher.getInstance(ALGORITMO_ASIMETRICO);
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
		return cipher.doFinal(Hex.decode(pLlaveCifrada));
	}

	private X509Certificate certificado() {
		X509Certificate certificado = null;
		try
		{
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			KeyPairGenerator keygen= KeyPairGenerator.getInstance("RSA");

			keygen.initialize(1024);

			KeyPair pair= keygen.generateKeyPair();
			setPrivateKey(pair.getPrivate());
			setPublicKey(pair.getPublic());

			BigInteger suma= BigInteger.valueOf(0);
			for (int i = 5; i < 5000; i++)
			{
				if(i%5==0)
				{
					suma=suma.add(BigInteger.valueOf(i));
				}
			}

			//numero serial del certificado
			BigInteger serialNumber=suma;

			X509V3CertificateGenerator certifGen= new X509V3CertificateGenerator();
			X500Principal dnName= new X500Principal("CN=Test Certificate");
			certifGen.setSerialNumber(serialNumber);
			certifGen.setIssuerDN(dnName);
			certifGen.setNotBefore(new Date(System.currentTimeMillis()-20000));
			certifGen.setNotAfter(new Date(System.currentTimeMillis()+20000));
			certifGen.setSubjectDN(dnName);
			certifGen.setPublicKey(pair.getPublic());
			certifGen.setSignatureAlgorithm("SHA256withRSA");
			certifGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
			certifGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyEncipherment) );
			certifGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
			certifGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name,"test@test.test")));
			X509Certificate cert= certifGen.generateX509Certificate(pair.getPrivate(), "BC");

			certificado=cert;
			
		}
		catch (Exception e)
		{
			System.out.println("Error en generación de certificado " + e.getMessage());
		}
		return certificado;
	}
	

	public static void setPrivateKey(PrivateKey pPrivada) 
	{
		privateKey = pPrivada;
	}

	public static void setPublicKey(PublicKey pPublica) 
	{
		publicKey = pPublica;
	}
	
	public static PrivateKey getPrivateKey() 
	{
		return privateKey;
	}

}
