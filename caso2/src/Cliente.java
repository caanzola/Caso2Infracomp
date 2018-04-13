import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
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
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
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
					escritor.println(CERTIFICADO);
					java.security.cert.X509Certificate cert = certificado();
					System.out.println("Certificado: "+cert);
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
			
			
			// yesterday
	        Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
	        // in 2 years
	        Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

	        // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
	        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
	        keyPairGenerator.initialize(1024, new SecureRandom());

	        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

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
	        
		    
			/**
			 KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		        keyPairGenerator.initialize(1024, new SecureRandom());

		        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

			// build a certificate generator
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			X500Principal dnName = new X500Principal("cn=example");

			// add some options
			certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
			certGen.setSubjectDN(new X509Name("dc=name"));
			certGen.setIssuerDN(dnName); // use the same
			// yesterday
			certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
			// in 2 years
			certGen.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
			certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

			// finally, sign the certificate with the private key of the same KeyPair
			certificado = certGen.generate(keyPair.getPrivate(), "BC");*/
			
		}
		catch (Exception e)
		{
			System.out.println("Error en generación de certificado " + e.getMessage());
		}
		return certificado;
	}

}
