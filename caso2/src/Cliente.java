import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.PrincipalUtil;
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
import org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory;

public class Cliente 
{

	private final static String CERTIFICADO = "CERTCLNT";
	private final static String CERTIFICADO_RECIBIDO = "CERTSRV";
	private final static String OK = "ESTADO:OK";
	private final static String ALGORITMO_ASIMETRICO="RSA";
	private final static String ALGORITMO_SIMETRICO="AES";
	private final static String ALGORITMO_HMAC="HMACSHA1";
	private final static String PADDING="AES/ECB/PKCS5Padding";
	private final static String POSICION ="41 24.2028, 2 10.4418"; 
	private final static int PUERTO = 8080;  
	private static SecretKey lls;
	private static PrivateKey privateKey;
	private static PublicKey publicKey;
	private static PublicKey publicKeySer;
	private static byte[] llaveSimetrica;

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
					// GENERAR Y ENVIAR DEL CERTIFICADO AL SERVIDOR
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
							try
							{
								// RECIBIR Y VERIFICAR EL CERTIFICADO QUE ENVIA EL SERVIDOR
								byte[] certificado = new byte[1024];
								socket.getInputStream().read(certificado);
								X509Certificate certSer = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificado));
								publicKeySer = certSer.getPublicKey();
								certSer.verify(publicKeySer);
								escritor.println(OK);
							}
							catch (Exception e) 
							{
								e.printStackTrace();
								escritor.println("ESTADO:ERROR");
							}
						}

						fromServer = lector.readLine();

						if(fromServer != null)
						{
							System.out.println("Servidor: " + fromServer);
							String llaveSimetricaCifradaHexa = fromServer.split(":")[1];
							
							// DESCIFRAR LA LLAVE SIMETRICA
							llaveSimetrica = descifrarLlaveSimetrica(llaveSimetricaCifradaHexa);
							// ENVIAR LAS COORDENADAS CIFRADAS
							enviarCoordenadasCifradas(escritor);
							//ENVIAR EL CODIGO DE INTEGRIDAD
							enviarCodigoDeIntegridad(escritor);
							
							fromServer = lector.readLine();
							if(fromServer.equals(OK))
							{
								System.out.println("FIN DE LA COMUNICACION");
								ejecutar = false;
							}
							else
							{
								System.out.println("HUBO UN ERROR");
							}
						}

					}
				}
			}
			escritor.close();
			lector.close();
			socket.close();
		}
		catch(Exception e)
		{
			System.out.println("Error " + e.getMessage());
			System.exit(1);
		}
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

	private static void enviarCoordenadasCifradas(PrintWriter escritor) throws Exception 
	{
		Cipher cipher1 = Cipher.getInstance(ALGORITMO_SIMETRICO);
		SecretKeySpec keySpec = new SecretKeySpec(llaveSimetrica, ALGORITMO_SIMETRICO);
		cipher1.init(Cipher.ENCRYPT_MODE, keySpec);

		String posicion="41 24.2028, 2 10.4418";

		escritor.println("ACT1:"+Hex.toHexString(cipher1.doFinal((posicion).getBytes())));
	}

	private static byte[] descifrarLlaveSimetrica(String pLlaveCifrada) throws Exception
	{
		Cipher cipher = Cipher.getInstance(ALGORITMO_ASIMETRICO);
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
		return cipher.doFinal(Hex.decode(pLlaveCifrada));
	}
	
	private static X509Certificate certificado() 
	{
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
