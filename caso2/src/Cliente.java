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
					escritor.print(CERTIFICADO);
					java.security.cert.X509Certificate cert = certificado();
					System.out.println("Certificado: "+cert);
					byte[] mybyte = cert.getEncoded();
					System.out.println("llega aca");
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
			// generate a key pair
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGenerator.initialize(4096, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			Provider bcProvider = new BouncyCastleProvider();
		    Security.addProvider(bcProvider);

		    long now = System.currentTimeMillis();
		    Date startDate = new Date(now);

		    X500Name dnName = new X500Name("x500 name");
		    BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

		    Calendar calendar = Calendar.getInstance();
		    calendar.setTime(startDate);
		    calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

		    Date endDate = calendar.getTime();
		    
		    String signatureAlgorithm = "SHA1WithRSA";
		    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
		    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());
		    
		    // build BouncyCastle certificate
		    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
		        .build(keyPair.getPrivate());
		    X509CertificateHolder holder = certBuilder.build(signer);

		    // convert to JRE certificate
		    JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		    converter.setProvider(new BouncyCastleProvider());
		    certificado = converter.getCertificate(holder);
		    **/
			
			/**
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
