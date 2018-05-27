package implementation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64Encoder;
import code.GuiException;
import gui.Constants;
import gui.GuiInterfaceV3;
import java.security.PrivateKey;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import utils.MyCodeUtils;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {

	private static final String KEYSTORE_TYPE = "jks";
	private static final String KEYSTORE_PASSWORD = "password";
	private static final String KEYSTORE_PATH = "keystore." + KEYSTORE_TYPE;
	private static final String ROOT_TRUSTED_CERT = "ETFrootCA";
	private static KeyStore keyStore;
	private static final char[] keyStorePassword = KEYSTORE_PASSWORD.toCharArray();

	
	private SubjectPublicKeyInfo signingSpki = null;
	
	public MyCode(boolean[] algorithmConf, boolean[] extensionsConf, boolean extensionsRules) throws GuiException {
		super(algorithmConf, extensionsConf, extensionsRules);	
		
	}

	@Override
	public boolean canSign(String keypairName) {	
		try {

			if (!keyStore.containsAlias(keypairName)) {
				return false;
			}
			//Getting certificate from certificate store.
			java.security.cert.Certificate cert = keyStore.getCertificate(keypairName);

			//Converting certificate in BC format.
			X509CertificateHolder x509 = new X509CertificateHolder(cert.getEncoded());

			//Getting basic constraints extension.
			Extension bcExt = x509.getExtension(Extension.basicConstraints);
                        Extension keyUsageExt = x509.getExtension(Extension.keyUsage);
			BasicConstraints bc = null;
			if (bcExt != null) {
				bc = BasicConstraints.fromExtensions(new Extensions(bcExt));
			}
                        KeyUsage keyUsage = null;
                        if (keyUsageExt != null) {
                            
                            keyUsage = KeyUsage.fromExtensions(new Extensions(keyUsageExt));
                        }
                        
                        boolean bcCa = bc != null ? bc.isCA() : false;
                        boolean kuCa = keyUsage != null ? keyUsage.hasUsages(5) : false;
                        
                        return bcCa || kuCa;

		}
		catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return false;
		}

	}

	@Override
	public boolean exportCSR(String file, String keypairName, String algorithm) {

		try {
			if (!keyStore.containsAlias(keypairName)) {
				return false;
			}

			if (!keyStore.isKeyEntry(keypairName)) {
				return false;
			}

			//Checking if file with provided name already exists.
			File f = new File(file);
			if (f.exists()) {
				f.delete();
			}

			//Checking if provided file name is name of directory.
			if (f.isDirectory()) {
				return false;
			}

			//Getting certificate from certificate store.
			java.security.cert.Certificate cert = keyStore.getCertificate(keypairName);

			CertificateFactory factory = new CertificateFactory();
			X509Certificate javaCert = (X509Certificate) factory.engineGenerateCertificate(new ByteArrayInputStream(cert.getEncoded()));

			//Converting certificate in BC format.
			X509CertificateHolder x509 = new X509CertificateHolder(cert.getEncoded());

			//Getting subject info
			X500Name subjectInfo = x509.getSubject();

			//Returning false if subject info wasn't acquired.
			if (subjectInfo == null) return false;

			//Getting public key.
			PublicKey publicKey = javaCert.getPublicKey();

			//Creating CSR builder.
			JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subjectInfo, publicKey);

			//Coping extensions from key pair stored in key store in CSR.
			@SuppressWarnings("unchecked")
			List<ASN1ObjectIdentifier> oids = x509.getExtensionOIDs();

			Iterator<ASN1ObjectIdentifier> oidIterator = oids.iterator();

			while(oidIterator.hasNext()) {
				ASN1ObjectIdentifier oid = oidIterator.next();
				Extension ext = x509.getExtension(oid);
				csrBuilder.addAttribute(oid, ext);
			}

			//Creating content signer.
			ContentSigner signer = null;

			//Getting private key.
			java.security.PrivateKey privateKey = (PrivateKey)keyStore.getKey(keypairName, keyStorePassword);

			signer = new JcaContentSignerBuilder(algorithm).build(privateKey);

			PKCS10CertificationRequest csr = csrBuilder.build(signer);

			try (FileOutputStream output = new FileOutputStream(f)) {
				output.write(csr.getEncoded());
			}

			return true;

		}
		catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			e.printStackTrace();
			return false;
		}

	}

	@Override
	public boolean exportCertificate(String file, String keypairName, int encoding, int format) {
		File f = new File(file);
		
		if (f.isDirectory()) {
			GuiInterfaceV3.reportError("Entered file is directory.");
		}
		if (f.exists()) {
			f.delete();
		}
		//TODO: Kada se importuje sertifikat kao csr, ako je u keystore-u sertifikat kojim je on potpisan, da li treba dohvatiti i taj sertifikat?
		try (FileOutputStream output = new FileOutputStream(f)){
			if (!keyStore.containsAlias(keypairName)) {
				GuiInterfaceV3.reportError("Certificate with alias " + keypairName + " doesn't exist.");
				return false;
			}

			java.security.cert.Certificate[] certs = null;
			byte[] encoded = null;
			if (format == 0) {
				
				java.security.cert.Certificate cert = keyStore.getCertificate(keypairName);
				if (cert == null) {
					GuiInterfaceV3.reportError("Certificate not found.");
					return false;
				}
				
				encoded = cert.getEncoded();
			}
			else {
				certs = keyStore.getCertificateChain(keypairName);
				
				if (certs == null) {
					GuiInterfaceV3.reportError("Certificate chain with alias " + keypairName + " wasn't found.");
					return false;
				}
				
				for (int i = 0; i < certs.length; i++) {
					byte[] enc = certs[i].getEncoded();					
					int newLen = enc.length + encoded.length;
					byte[] temp = new byte[newLen];
					
					for(int j = 0; j < encoded.length; j++) {
						temp[j] = encoded[j];
					}
					
					for (int j = encoded.length; j < temp.length; j++) {
						temp[j] = enc[j - encoded.length];
					}
					
					encoded = temp;
				}
			}
			
					
			if (encoding == 0) {
				output.write(encoded);
			}
			
			else {
				try (OutputStreamWriter writer = new OutputStreamWriter(output); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
					String begin = "-----BEGIN CERTIFICATE-----\n";
					String end = "\n-----END CERTIFICATE-----";
					writer.write(begin.toCharArray(), 0, begin.length());			
					Base64Encoder b64 = new Base64Encoder();
					b64.encode(encoded, 0, encoded.length, out);	
					byte[] bytes = out.toByteArray();
					String pem = new String(bytes);
					writer.write(pem);
					writer.write(end);
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			GuiInterfaceV3.reportError(e); 
			return false;
		}
		return true;
	}

	@Override
	public boolean exportKeypair(String keypairName, String file, String password) {
		File f = new File(file);

		
		try {
			if (!keyStore.containsAlias(keypairName)) {
				GuiInterfaceV3.reportError("Key store doesn't contain key pair with alias " + keypairName + ".");
				return false;
			}
		} catch (Exception e) {
			
			GuiInterfaceV3.reportError(e);
			return false;
		}
		
		//Checking if file exists of if file is directory.
		if (f.isDirectory()) {
			GuiInterfaceV3.reportError(file + " is a directory.");
			return false;
		}
	
		if (f.exists()) {
			f.delete();
		}

		try {

			//Creating new key store with pkcs12 type.
			KeyStore ks = KeyStore.getInstance("pkcs12");

			//Importing .p12 file in newly created key store.
			ks.load(null, password.toCharArray());
			
			//Getting certificate
			java.security.cert.Certificate[] cert = null;// = new java.security.cert.Certificate[1];
			
			if (keyStore.isKeyEntry(keypairName)) {
				//Storing certificate in array.
				cert = keyStore.getCertificateChain(keypairName);
				
				//Getting private key.
				java.security.Key privateKey = null;
				if (keyStore.isKeyEntry(keypairName)) {
					privateKey = keyStore.getKey(keypairName, keyStorePassword);
				}
                                cert = new java.security.cert.Certificate[1];
                                cert[0] = keyStore.getCertificateChain(keypairName)[0];
				ks.setKeyEntry(keypairName, privateKey, password.toCharArray(), cert);
			}
			else {
				cert = new java.security.cert.Certificate[1];
				cert[0] = keyStore.getCertificate(keypairName);
				
				ks.setCertificateEntry(keypairName, cert[0]);
		
			}
			//Saving key pair to .p12 file.
			MyCodeUtils.storeKeystore(ks, file, password.toCharArray());

			return true;
		} catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return false;
		}

	}

	@Override
	public String getCertPublicKeyAlgorithm(String keypairName) {
		try {
			if (!keyStore.containsAlias(keypairName)) {
				return null;
			}
			//Getting certificate from certificate store.
			java.security.cert.Certificate cert = keyStore.getCertificate(keypairName);
		
			//Converting certificate in BC format.
			X509CertificateHolder x509 = new X509CertificateHolder(cert.getEncoded());

			//Getting subject public key info.
			SubjectPublicKeyInfo spki = x509.getSubjectPublicKeyInfo();

			//Getting algorithm identifier.
			AlgorithmIdentifier spkiId = spki.getAlgorithm();

			//Finding algorithm name using algorithm OID.
			String publicKeyAlgorithmName = new DefaultAlgorithmNameFinder().getAlgorithmName(spkiId.getAlgorithm());

			return publicKeyAlgorithmName;
		}
		catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return null;
		}
	}

	@Override
	public String getCertPublicKeyParameter(String keypairName) {
		try {
			if (!keyStore.containsAlias(keypairName)) {
				return null;
			}
			
			//Getting certificate from certificate store.
			java.security.cert.Certificate cert = keyStore.getCertificate(keypairName);

			//Converting java.security.cert.Certificate to bouncy castle certificate.
			CertificateFactory factory = new CertificateFactory();
			X509Certificate javaCert = (X509Certificate) factory.engineGenerateCertificate(new ByteArrayInputStream(cert.getEncoded()));

                        int bitLen = 0;
                        
			//Getting public key.
			PublicKey pk = javaCert.getPublicKey();
                        if (pk instanceof BCRSAPublicKey) {
                            BCRSAPublicKey bcPk = (BCRSAPublicKey)pk;
                            //Getting public key parameter.
                            bitLen = bcPk.getModulus().bitLength();
                        }
                        else if (pk instanceof BCDSAPublicKey){
                            BCDSAPublicKey bcPk = (BCDSAPublicKey)pk;
                            bcPk.getY().bitLength();
                            //Getting public key parameter.
                            bitLen = bcPk.getY().bitLength() + 1;
                        }

			return bitLen + "";
		}
		catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return null;
		}
	}

	@Override
	public String getSubjectInfo(String keypairName) {
		try {
			if (!keyStore.containsAlias(keypairName)) {
				return null;
			}

			//Getting certificate from certificate store
			java.security.cert.Certificate cert = keyStore.getCertificate(keypairName);

			//Converting certificate in BC format
			X509CertificateHolder x509 = new X509CertificateHolder(cert.getEncoded());

			//Getting object containing subject info
			X500Name subject = x509.getSubject();

			if (subject != null) {
				return subject.toString();
			}
			else {
				return null;
			}
		}
		catch (Exception e) {
			GuiInterfaceV3.reportError(e);
		}
		return null;
	}

	@Override
	public boolean importCAReply(String file, String keypairName) {
		File f = new File(file);
		
		if (!f.exists()) {
			GuiInterfaceV3.reportError("Provided file path doesn't exists.");
			return false;
		}
		
		try (FileInputStream input = new FileInputStream(f)) {
			//Reading file.
			CMSSignedData signedData = new CMSSignedData(input);
			
			//Getting signed certificate.
			CMSTypedData ctd = signedData.getSignedContent();
			
			if (ctd.getContentType() != PKCSObjectIdentifiers.x509Certificate || !(ctd instanceof CMSProcessableByteArray)) {
				GuiInterfaceV3.reportError("Unknown signed content.");
				return false;
			}

			//Getting signing certificates.
			CollectionStore<X509CertificateHolder> certs = (CollectionStore<X509CertificateHolder>)signedData.getCertificates();
			
			//Reading signed certificate as byte array.
			CMSProcessableByteArray data = (CMSProcessableByteArray)ctd;
			InputStream in = data.getInputStream();
			
			//Converting byte array to certificate object.
			CertificateFactory factory = new CertificateFactory();
			
			java.security.cert.Certificate javaCert = factory.engineGenerateCertificate(in);
			X509CertificateHolder signedCert = new X509CertificateHolder(javaCert.getEncoded());
			
			java.security.cert.Certificate oldJavaCert = keyStore.getCertificate(keypairName);
			X509CertificateHolder oldCert = new X509CertificateHolder(oldJavaCert.getEncoded());
			
			//Comparing if imported csr matches key pair that we want to sign.
			if (!signedCert.getSubject().toString().equals(oldCert.getSubject().toString())) {
				GuiInterfaceV3.reportError("Diferent subjects in signing certificate and CA reply.");
				return false;
			}
			
			//Setting signed certificate in key store.
			if (keyStore.isKeyEntry(keypairName)) {
				Key key = keyStore.getKey(keypairName, keyStorePassword);
				
				keyStore.deleteEntry(keypairName);
				
				Iterator<X509CertificateHolder> it = certs.iterator();
				ArrayList<java.security.cert.Certificate> listChain = new ArrayList<>();
				while(it.hasNext()) {
					listChain.add(factory.engineGenerateCertificate(new ASN1InputStream(it.next().getEncoded())));
				}
				
				
				java.security.cert.Certificate[] chain = new java.security.cert.Certificate[listChain.size() + 1];
				chain[0] = javaCert;
				for(int i = 0; i < listChain.size(); i++) {
					chain[i + 1] = listChain.get(i);
				}
				
				keyStore.setKeyEntry(keypairName, key, keyStorePassword, chain);
			}
			else {
				keyStore.deleteEntry(keypairName);
				
				keyStore.setCertificateEntry(keypairName, javaCert);
			}
			
			MyCodeUtils.storeKeystore(keyStore, KEYSTORE_PATH, keyStorePassword);
			
			System.out.print("hehe");
			return true;
		}
		catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return false;
		}

	}

	@Override
	public String importCSR(String file) {
		File f = new File(file);
		
		if (!f.exists() || f.isDirectory()) {
			return null;
		}
		
		try (FileInputStream input = new FileInputStream(f)) {
			byte[] decoded = new byte[input.available()]; 
			input.read(decoded);
			
			//byte[] decoded = Base64.getDecoder().decode(encoding);
			//ASN1InputStream in = new ASN1InputStream(keyBytes);
			
			
			BcPKCS10CertificationRequest csr = new BcPKCS10CertificationRequest(decoded);
			
			X500Name subject = csr.getSubject();
			AlgorithmIdentifier signatureAlgorithm = csr.getSignatureAlgorithm();
			String sigAlgName = new DefaultAlgorithmNameFinder().getAlgorithmName(signatureAlgorithm);
			signingSpki = csr.getSubjectPublicKeyInfo();
			String retValue = subject.toString() + "," + "SA=" + sigAlgName.replaceAll("WITH", "with");
			
			return retValue;
			
		}
		catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return null;
		}

	}

	@Override
	public boolean importCertificate(String file, String keypairName) {
		File f = new File(file);

		if (!f.exists() || f.isDirectory()) {
			return false;
		}
		
		try (FileInputStream input = new FileInputStream(f)){
			
			//Two certificates with same name can't exist in key store.
			if (keyStore.containsAlias(keypairName)) {
				GuiInterfaceV3.reportError("Certificate with name " + keypairName + " already exsists.");
				return false;
			}

			//Creating factory for reading certificate, and reading certificate.
			CertificateFactory factory = new CertificateFactory();
			java.security.cert.Certificate cert = factory.engineGenerateCertificate(input);
			
			
			//Saving certificate in local key store.
			keyStore.setCertificateEntry(keypairName, cert);
			MyCodeUtils.storeKeystore(keyStore, KEYSTORE_PATH, keyStorePassword);
			return true;
		}
		catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return false;
		}
	}

	@Override
	public boolean importKeypair(String keypairName, String file, String password) {

		//Creating file handle.
		File f = new File(file);

		//Checking if file exists of if file is directory.
		if (!f.exists() || f.isDirectory()) {
			return false;
		}


		try (FileInputStream input = new FileInputStream(f)){

			//Creating new key store with pkcs12 type.
			KeyStore ks = KeyStore.getInstance("pkcs12");

			//Importing .p12 file in newly created key store.
			ks.load(input, password.toCharArray());

			//Getting alias of first certificate in chain.
			Enumeration<String> aliases = ks.aliases();

			if (aliases == null || !aliases.hasMoreElements()) {
				return false;
			}
			String alias = aliases.nextElement();

			//Getting certificate chain.
			java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);

			//If there is no certificate in file method returns false, as importing failed.
			if (chain == null) return false;

			//Getting private key associated with imported key pair.
			Key key = null;
			if (ks.isKeyEntry(alias)) {
				key = ks.getKey(alias, password.toCharArray());
			}
			
			//X509CertificateHolder cert = new X509CertificateHolder(chain[0].getEncoded());
			
			/*BasicConstraints bc = null;
			try {
				bc = BasicConstraints.fromExtensions(new Extensions(cert.getExtension(Extension.basicConstraints)));
			}
			catch (Exception e) {
				//swallow exception
			}
			if (cert.getSubject().toString().contains("CN=ETFrootCA")) {
				trustedCerts.put(keypairName, cert);
			}
			else if (bc != null && bc.isCA()){
				X500Name issuerName = cert.getIssuer();
				
				Iterator<Entry<String, X509CertificateHolder>> mapIterator = trustedCerts.entrySet().iterator();
				
				while(mapIterator.hasNext()) {
					Entry<String, X509CertificateHolder> entry = mapIterator.next();
					
					if (entry.getValue().getSubject().toString().equals(issuerName.toString())) {
						trustedCerts.put(keypairName, cert);
					}
				}
			}
			*/
			//Coping imported key pair in local key store.
			if (ks.isKeyEntry(alias)) {
				keyStore.setKeyEntry(keypairName, key, keyStorePassword, chain);
			}
			else {
				keyStore.setCertificateEntry(keypairName, chain[0]);
			}

			MyCodeUtils.storeKeystore(keyStore, KEYSTORE_PATH, keyStorePassword);

			return true;
		} catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return false;
		}

	}

	@Override
	public int loadKeypair(String keypairName) {
		try {
			if (!keyStore.containsAlias(keypairName)) {
				return -1;
			}

			java.security.cert.Certificate cert = keyStore.getCertificate(keypairName);

			CertificateFactory factory = new CertificateFactory();
			X509Certificate javaCert = (X509Certificate) factory.engineGenerateCertificate(new ByteArrayInputStream(cert.getEncoded()));
			X509CertificateHolder x509 = new X509CertificateHolder(cert.getEncoded());

                        
                        System.out.println(ASN1Dump.dumpAsString(javaCert));
			int version = x509.getVersionNumber();

			//Getting certificate 
			BigInteger serialNumber = x509.getSerialNumber();

			//Getting certificate validation period.
			Date notAfter = x509.getNotAfter();
			Date notBefore = x509.getNotBefore();

			//Getting issuer info and subject info
			X500Name subject = x509.getSubject();
			X500Name issuer = x509.getIssuer();

			//Getting issuer alternative names constraint
			String issuerAltNames = null;
			Extension ian = x509.getExtension(Extension.issuerAlternativeName);
			issuerAltNames = MyCodeUtils.parseIssuerAlternativeName(javaCert);

			//Getting basic constraints
			Extension bcExt = x509.getExtension(Extension.basicConstraints);
			BasicConstraints bc = null;
			if (bcExt != null) {
				bc = BasicConstraints.fromExtensions(new Extensions(bcExt));
			}

			//Getting subject key identifier constraint
			Extension skiExt = x509.getExtension(Extension.subjectKeyIdentifier);
			SubjectKeyIdentifier ski = null;
			if (skiExt != null) {
				ski = SubjectKeyIdentifier.fromExtensions(new Extensions(skiExt));
			}

			//Algorithm name finder that finds algorithm name based on provided algorithm OID.
			DefaultAlgorithmNameFinder algNameFinder = new DefaultAlgorithmNameFinder();

			//Getting digest signature algorithm name.
			AlgorithmIdentifier digestAlgorithmId = x509.getSignatureAlgorithm();
			String digestAlgorithmName = algNameFinder.getAlgorithmName(digestAlgorithmId.getAlgorithm());
			if (digestAlgorithmName != null) {
				digestAlgorithmName = digestAlgorithmName.replaceAll("WITH", "with");
			}

			//Getting public key algorithm name and parameter.
			//SubjectPublicKeyInfo spki = x509.getSubjectPublicKeyInfo();
//			AlgorithmIdentifier spkiId = spki.getAlgorithm();
//			String publicKeyAlgorithmName = algNameFinder.getAlgorithmName(spkiId.getAlgorithm());

                        String publicKeyAlgorithmName = this.getCertPublicKeyAlgorithm(keypairName);
                        
                        String publicKeyParameter = null;
			publicKeyParameter = this.getCertPublicKeyParameter(keypairName);
			
			//Setting parsed data.
			access.setSubject(subject.toString());
			access.setIssuer(issuer.toString());
			access.setNotAfter(notAfter);
			access.setNotBefore(notBefore);
			access.setVersion(version - 1);
			access.setSerialNumber(serialNumber.toString());
			access.setIssuerSignatureAlgorithm(digestAlgorithmName);
			if (digestAlgorithmName != null) {
				access.setPublicKeyDigestAlgorithm(digestAlgorithmName);
			}

			if (publicKeyAlgorithmName != null) {
				access.setPublicKeyAlgorithm(publicKeyAlgorithmName);
				access.setSubjectSignatureAlgorithm(publicKeyAlgorithmName);
			}

			if (publicKeyParameter != null) {
				access.setPublicKeyParameter(publicKeyParameter);
			}


			if (ian != null && !"".equals(issuerAltNames)) {
				access.setAlternativeName(Constants.IAN, issuerAltNames);
				access.setCritical(Constants.IAN, ian.isCritical());
			}

			if (bcExt != null) {
				access.setCA(bc.isCA());
				access.setCritical(Constants.BC, bcExt.isCritical());
				if (bc.isCA() && (bc.getPathLenConstraint() != null)) {
					access.setPathLen(bc.getPathLenConstraint().toString());
				}
			}
			else {
				access.setCA(false);
			}

			if (ski != null) {
				access.setCritical(Constants.SKID, skiExt.isCritical());
				access.setEnabledSubjectKeyID(true);
				DEROctetString dos = new DEROctetString(ski.getKeyIdentifier());

				access.setSubjectKeyID(dos.toString().replaceFirst("#", ""));
			}
			
			if (MyCodeUtils.isTrusted(keyStore, keypairName, ROOT_TRUSTED_CERT)) {
				return 2;
			}
			else if (subject.toString().equals(issuer.toString())){
				return 0;
			}
			else {
				return 1;
			}
			
			

		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}


	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		KeyStore ks = null;
		FileInputStream input = null;
		FileOutputStream output = null;

		//if (Security.getProvider(KEYSTORE_TYPE) == null) {
		//	Security.insertProviderAt(new BouncyCastleProvider(), 1);
		//}
		try {
			ks = KeyStore.getInstance(KEYSTORE_TYPE);

			//Checking if local keystore was already created.
			File f = new File(KEYSTORE_PATH);
			if (!f.exists() || f.isDirectory()) {

				//If local keystore was't created, than we are creating empty keystore.
				ks.load(null, keyStorePassword);
				output = new FileOutputStream(f);
				ks.store(output, keyStorePassword);
			}
			else {

				//If keystore was already created we are loading file with file input stream.
				input = new FileInputStream(f);

				//Loading keystore file into keystore object.
				ks.load(input, keyStorePassword);
			}

			keyStore = ks;


		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		// Closing file streams
		finally {
			try {
				if (input != null) {
					input.close();
				}

				if (output != null) {
					output.close();
				}
			} catch (IOException e) {

				e.printStackTrace();
				return null;
			}
		}
		try {
			//Returning aliases from key store
			return keyStore.aliases();

		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean removeKeypair(String keypairName) {
		try {
			if (keyStore.containsAlias(keypairName)) {
				keyStore.deleteEntry(keypairName);
				MyCodeUtils.storeKeystore(keyStore, KEYSTORE_PATH, keyStorePassword);
				return true;
			}
			else {
				return false;
			}
		} catch (Exception e) {
			GuiInterfaceV3.reportError(e);
		}
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		try {
			KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE, BouncyCastleProvider.PROVIDER_NAME);
			ks.load(null, keyStorePassword);
			MyCodeUtils.storeKeystore(ks, KEYSTORE_PATH, keyStorePassword);
			keyStore = ks;
		} catch (Exception e) {
			GuiInterfaceV3.reportError(e);
		}
	}

	@Override 
	public boolean saveKeypair(String keypairName) {
		//TODO: BCRSA vidi kako se tu generise kljuc, to se koristi pri importu etf sertifikata.
		String subject = access.getSubject();

		Date notBefore = access.getNotBefore();
		Date notAfter = access.getNotAfter();

		boolean ca = access.isCA();
		boolean bcCritical = access.isCritical(Constants.BC);
		String pathLength = access.getPathLen();
		int pathLen = 0;


		String[] ian = access.getAlternativeName(Constants.IAN);
		boolean ianCritical = access.isCritical(Constants.IAN);

		boolean skiEnabled = access.getEnabledSubjectKeyID();	
		boolean skiCritical = access.isCritical(Constants.SKID);

		String publicKeyAlgorithm = access.getPublicKeyAlgorithm();
		String publicKeyParameter = access.getPublicKeyParameter();
		String digestAlgorithm = access.getPublicKeyDigestAlgorithm();

		String serialNumber = access.getSerialNumber();
		BigInteger serial = new BigInteger(serialNumber);

		//Generating keypair using RSA algorithm
		KeyPairGenerator kpg = null;
		KeyPair kp = null;

		int publicKeyBitLength = 0;
		try {
			publicKeyBitLength = Integer.parseInt(publicKeyParameter);	


			kpg = KeyPairGenerator.getInstance(publicKeyAlgorithm);
			kpg.initialize(publicKeyBitLength, new SecureRandom());
			kp = kpg.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			GuiInterfaceV3.reportError(e);
			return false;
		}

		//BCRSAPrivateCrtKey privateKey = (BCRSAPrivateCrtKey)kp.getPrivate();
		
		//BCRSAPublicKey publicK = (BCRSAPublicKey)kp.getPublic();
		//RSAKeyParameters publicKey = new RSAKeyParameters(false, publicK.getModulus(),publicK.getPublicExponent());
		
		//Parsing path length.
		boolean hasPath = false;
		try {
			pathLen = Integer.parseInt(pathLength);
			hasPath = true;
		}
		catch (Exception e) {
			pathLen = 0;
		}

		//Creating builder for generating certificate

		X509v3CertificateBuilder builder = null;
//		try {

			builder = new JcaX509v3CertificateBuilder(new X500Name(subject), serial, notBefore, notAfter, new X500Name(subject), kp.getPublic());
//		} catch (IOException e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
		
		BasicConstraints bc = null;
		if (ca && hasPath) {
			bc = new BasicConstraints(pathLen);
		}
		else {
			bc = new BasicConstraints(ca);
		}


		//Adding extensions
		try {
			builder.addExtension(Extension.basicConstraints, bcCritical, bc);

			//Adding issuer alternative names extension if names were entered
			GeneralNames generalNames = MyCodeUtils.createIssuerAlternativeName(ian);
			if (generalNames != null) {
				builder.addExtension(Extension.issuerAlternativeName, ianCritical, generalNames);
			}

			//Adding subject key identifier extension if enabled
			if (skiEnabled) {

				//builder.addExtension(Extension.subjectKeyIdentifier, false, SubjectKeyIdentifier.getInstance(new DEROctetString(kp.getPublic().getEncoded())));
				builder.addExtension(Extension.subjectKeyIdentifier, skiCritical, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(kp.getPublic()));
				//builder.addExtension(Extension.subjectKeyIdentifier, skiCritical, new BcX509ExtensionUtils().createSubjectKeyIdentifier(rsaKP.getPublic()));
			}
		} catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			return false;
		}

		ContentSigner signatureGenerator = null;
		try {
			//AlgorithmIdentifier signatureId = new DefaultSignatureAlgorithmIdentifierFinder().find(digestAlgorithm);
			//AlgorithmIdentifier digestId = new DefaultDigestAlgorithmIdentifierFinder().find(signatureId);

			signatureGenerator = new JcaContentSignerBuilder(digestAlgorithm).build(kp.getPrivate());
			//signatureGenerator = new BcRSAContentSignerBuilder(signatureId, digestId).build(privateKey);

			//Generating certificate
			X509CertificateHolder holder = builder.build(signatureGenerator);		

			//Converting certificate from bouncy castle specification to java specification
			Certificate cert = holder.toASN1Structure();		
			CertificateFactory certFact = new CertificateFactory();
		
			java.security.cert.Certificate x509 = certFact.engineGenerateCertificate(new ASN1InputStream(cert.getEncoded()));		
			java.security.cert.Certificate[] certArray = new java.security.cert.Certificate[1];
			
			certArray[0] = x509;

			//Storing certificate in local key store
			keyStore.setKeyEntry(keypairName, kp.getPrivate(), keyStorePassword, certArray);			
			MyCodeUtils.storeKeystore(keyStore, KEYSTORE_PATH, keyStorePassword);

		} catch (Exception e) {
			e.printStackTrace();
			GuiInterfaceV3.reportError(e);
			return false;
		}
		return true;
	}

	@SuppressWarnings("rawtypes")
	@Override
	public boolean signCSR(String file, String keypairName, String algorithm) {
		
		try {		
			java.security.cert.Certificate[] signerChain = keyStore.getCertificateChain(keypairName);
			
			if (signerChain == null) {
				GuiInterfaceV3.reportError("Issuer not found.");
				return false;
			}
			
			X509CertificateHolder issuerCert = new X509CertificateHolder(signerChain[0].getEncoded());
			PrivateKey privateKey = (PrivateKey)keyStore.getKey(keypairName, keyStorePassword);
		
			if (privateKey == null) {
				GuiInterfaceV3.reportError("Private key not found.");
				return false;
			}
			
			//Creating signed data generator
			CMSSignedDataGenerator cmsGen = new CMSSignedDataGenerator();
			
			//Adding certificate to collection
			
			ArrayList<java.security.cert.Certificate> certs = new ArrayList<>();
			for(java.security.cert.Certificate cert: signerChain) {
				certs.add(cert);
			}
			
			//Adding cert to new store which will be used for generating signature
			Store certStore = new JcaCertStore(certs);
			ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(privateKey);


			String subject = access.getSubject();

			Date notBefore = access.getNotBefore();
			Date notAfter = access.getNotAfter();

			boolean ca = access.isCA();
			boolean bcCritical = access.isCritical(Constants.BC);
			String pathLength = access.getPathLen();
			int pathLen = 0;


			String[] ian = access.getAlternativeName(Constants.IAN);
			boolean ianCritical = access.isCritical(Constants.IAN);

			boolean skiEnabled = access.getEnabledSubjectKeyID();	
			boolean skiCritical = access.isCritical(Constants.SKID);

			String serialNumber = access.getSerialNumber();
			BigInteger serial = new BigInteger(serialNumber);

			
			//Parsing path length.
			boolean hasPath = false;
			try {
				pathLen = Integer.parseInt(pathLength);
				hasPath = true;
			}
			catch (Exception e) {
				pathLen = 0;
			}

			
			X509v3CertificateBuilder builder = null;
			builder = new X509v3CertificateBuilder(issuerCert.getSubject(), serial, notBefore, notAfter, new X500Name(subject), signingSpki);

			BasicConstraints bc = null;
			if (ca && hasPath) {
				bc = new BasicConstraints(pathLen);
			}
			else {
				bc = new BasicConstraints(ca);
			}
			

			//Adding extensions
			try {
				builder.addExtension(Extension.basicConstraints, bcCritical, bc);

				//Adding issuer alternative names extension if names were entered
				GeneralNames generalNames = MyCodeUtils.createIssuerAlternativeName(ian);
				if (generalNames != null) {
					builder.addExtension(Extension.issuerAlternativeName, ianCritical, generalNames);
				}

				//Adding subject key identifier extension if enabled
				if (skiEnabled) {

					//builder.addExtension(Extension.subjectKeyIdentifier, false, SubjectKeyIdentifier.getInstance(new DEROctetString(kp.getPublic().getEncoded())));
					builder.addExtension(Extension.subjectKeyIdentifier, skiCritical, new BcX509ExtensionUtils().createSubjectKeyIdentifier(signingSpki));
					//builder.addExtension(Extension.subjectKeyIdentifier, skiCritical, new BcX509ExtensionUtils().createSubjectKeyIdentifier(rsaKP.getPublic()));
				}
			} catch (Exception e) {
				GuiInterfaceV3.reportError(e);
				return false;
			}


			Certificate cert = null;
			try {

				//Generating certificate
				X509CertificateHolder holder = builder.build(signer);		

				//Converting certificate from bouncy castle specification to java specification
				cert = holder.toASN1Structure();		
	
	
			} catch (Exception e) {
				e.printStackTrace();
				GuiInterfaceV3.reportError(e);
				return false;
			}
			
			//Adding signer to cms generator.
			cmsGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, new X509CertificateHolder(signerChain[0].getEncoded())));
			
			//adding signer chain to cms generator
			cmsGen.addCertificates(certStore);
			
			//Adding signed certificate.
			CMSSignedData signed = cmsGen.generate(new CMSProcessableByteArray(PKCSObjectIdentifiers.x509Certificate, cert.getEncoded()),true);
			File f = new File(file);
			if (f.exists()) {
				f.delete();
			}

			//Writing content to file.
			try(OutputStream out = new FileOutputStream(f);) {
				out.write(signed.getEncoded());
			}
			
			return true;
		} catch (Exception e) {
			GuiInterfaceV3.reportError(e);
			e.printStackTrace();
		}
		return false;
	}
}
