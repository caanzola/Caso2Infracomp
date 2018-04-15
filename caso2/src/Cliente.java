import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.jcajce.*;

public class Cliente 
{

	private final static String CERTIFICADO = "CERTCLNT";
	private final static String CERTIFICADO_RECIBIDO = "CERTSRV";
	private final static String OK = "ESTADO:OK";
	private final static String ERROR = "ESTADO:ERROR";
	private final static String ALGORITMO_ASIMETRICO="RSA";
	private final static String ALGORITMO_SIMETRICO="AES";
	private final static String PADDING="AES/ECB/PKCS5Padding";
	private final static String POSICION ="41 24.2028, 2 10.4418"; 
	private final static int PUERTO = 8080;  
	private static KeyPair realKeyPair;
	private static String simetricKey;

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
			boolean envioCertificado = false;
			while (ejecutar) 
			{
				System.out.print("Escriba el mensaje para enviar:");
				fromUser = stdIn.readLine();
				if(fromUser != null && fromUser.equals(CERTIFICADO))
				{
					escritor.println(CERTIFICADO);
					java.security.cert.X509Certificate cert = certificado();
					byte[] mybyte = cert.getEncoded();
					socket.getOutputStream().write(mybyte);
					socket.getOutputStream().flush();
					envioCertificado = true;
				}
				else
				{
					escritor.println(fromUser);
				}


				if ((fromServer = lector.readLine()) != null) 
				{
					System.out.println("Servidor: " + fromServer);
					if(envioCertificado)
					{
						fromServer = lector.readLine();
						System.out.println("Servidor: " +fromServer);
						if(fromServer != null && fromServer.equals(CERTIFICADO_RECIBIDO))
						{
							byte[] recievedData = new byte[1024];
							BufferedInputStream bis = new BufferedInputStream(socket.getInputStream());
							DataInputStream dis=new DataInputStream(socket.getInputStream());
							int inl = bis.read(recievedData);
							boolean recibioCertificado = false;
							while ((inl) != -1 && !recibioCertificado)
							{
								recibioCertificado = true;
								escritor.println(OK);
							}

							if(!recibioCertificado)
							{
								escritor.println(ERROR);
							}
						}

						fromServer = lector.readLine();

						if(fromServer != null)
						{
							System.out.println("Servidor: " + fromServer);
							String llaveSimetricaCifradaHexa = fromServer.split(":")[1];
							byte[] encodedKey = hexToByte(llaveSimetricaCifradaHexa);
							simetricKey = descifrar(encodedKey);
							System.out.println("La llave simetrica es " + simetricKey);
							String posicionCifrada = cifrar(POSICION).toString();
							System.out.println("Pos cifrada " + posicionCifrada);
							String posicionCifradaEnHexadecimal = textToHex(posicionCifrada);
							escritor.println("ACT1:"+posicionCifradaEnHexadecimal);
							String hash = hash().toString();
							String hashCifrado = cifrarAsimetrico(hash).toString();
							escritor.println("ACT2:"+hashCifrado);
							fromServer = lector.readLine();
							if(fromServer.equals(OK))
							{
								System.out.println("FIN DE LA COMUNICACION");
								ejecutar = false;
							}
						}

					}
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

	private static byte[] cifrarAsimetrico(String hash) {
		try 
		{
			Cipher cipher = Cipher.getInstance(ALGORITMO_ASIMETRICO, "BC");
			byte [] clearText = hash.getBytes();
			String s1 = new String (clearText);
			cipher.init(Cipher.ENCRYPT_MODE, realKeyPair.getPublic());
			byte [] cipheredText = cipher.doFinal(clearText);
			System.out.println("clave cifrada: " + cipheredText);
			return cipheredText;
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	private static byte[] hash() 
	{
		byte[] text = new byte[1024];
		try 
		{
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("Digite la información:");
			String dato = stdIn.readLine();
			text = dato.getBytes();
			String s1 = new String(text);
			System.out.println("dato original: " + s1);
			byte [] digest = getKeyedDigest(text);
			String s2 = new String(digest);
			System.out.println("digest: "+ s2);
			return digest;
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	private static byte[] getKeyedDigest(byte[] buffer) 
	{
		try 
		{
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			md5.update(buffer);
			return md5.digest();
		} 
		catch (Exception e) 
		{
			return null;
		}
	}

	private static String textToHex(String s) {
		
		 char[] ch = s.toCharArray();

	      StringBuilder builder = new StringBuilder();

	      for (char c : ch) {
	         int i = (int) c;
	         builder.append(Integer.toHexString(i).toUpperCase());
	      }

	      return builder.toString();
	}

	private static byte[] hexToByte(String s) 
	{
		 int len = s.length();
		    byte[] data = new byte[len / 2];
		    for (int i = 0; i < len; i += 2) {
		        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
		                             + Character.digit(s.charAt(i+1), 16));
		    }
		    return data;
	}

	public static byte[] cifrar(String texto) 
	{
		byte [] cipheredText;
		try 
		{
			Cipher cipher = Cipher.getInstance(PADDING, "BC");
			byte [] clearText = texto.getBytes();
			String s1 = new String (clearText);
			
			//Si le restamos 111 al tamaño de la llave si encripta y envia
			SecretKey desKey = new SecretKeySpec(simetricKey.getBytes(), 0, simetricKey.getBytes().length, ALGORITMO_SIMETRICO);
			
			System.out.println(Cipher.getMaxAllowedKeyLength(ALGORITMO_SIMETRICO));
			System.out.println(desKey.getEncoded().length);
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			cipheredText = cipher.doFinal(clearText);
			
			String s2 = new String (cipheredText);
			System.out.println("clave cifrada: " + s2);
			return cipheredText;
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}
	
	public static String descifrar(byte[] cipheredText) 
	{
		String textoDescifrado = null;
		try 
		{
			
			Cipher cipher = Cipher.getInstance(ALGORITMO_ASIMETRICO, "BC");
			cipher.init(Cipher.DECRYPT_MODE, realKeyPair.getPrivate());
			byte [] clearText = cipher.doFinal(cipheredText);
			textoDescifrado = new String(clearText);
		}
		catch (Exception e) 
		{
			System.out.println("Excepcion: " + e.getMessage());
		}
		
		return textoDescifrado;
	}

	private static X509Certificate certificado() 
	{
		X509Certificate certificado = null;
		try
		{
			Security.addProvider(new BouncyCastleProvider());

			// yesterday
			Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
			// in 2 years
			Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

			// GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGenerator.initialize(1024, new SecureRandom());

			java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
			realKeyPair = keyPair;

			// GENERATE THE X509 CERTIFICATE
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			X500Principal dnName = new X500Principal("CN=John Doe");

			certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
			certGen.setSubjectDN(dnName);
			certGen.setIssuerDN(dnName); // use the same
			certGen.setNotBefore(validityBeginDate);
			certGen.setNotAfter(validityEndDate);
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

			certificado = certGen.generate(keyPair.getPrivate(), "BC");
		}
		catch (Exception e)
		{
			System.out.println("Error en generación de certificado " + e.getMessage());
		}
		return certificado;
	}

}
