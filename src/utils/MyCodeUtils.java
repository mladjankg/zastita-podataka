package utils;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.StringJoiner;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;

import x509.v3.GuiV3;

public class MyCodeUtils {
	public static String join(char delimiter, String[] array) {
		if (array == null)
		{
			return "";
		}
		
		StringJoiner joiner = new StringJoiner(",");
		
		for(String elem:array) {
			joiner.add(elem);
		}

		return joiner.toString();
	}
	

	
	public static ASN1Primitive getASN1Primitive(byte[] encoded) throws IOException {
		try (ByteArrayInputStream byteInput = new ByteArrayInputStream(encoded);
				ASN1InputStream asn1Input = new ASN1InputStream(byteInput)) {
			return asn1Input.readObject();
		}
	}
	
	public static String parseIssuerAlternativeName(X509Certificate javaCert) throws IOException {
		StringBuilder sb = new StringBuilder();
		
		try {
			Collection<List<?>> ians = javaCert.getIssuerAlternativeNames();
			if (ians != null) {
				for(List<?> list: ians) {
					Integer fieldTag = null;
					String fieldValue = null;
					
					for(Object elem: list) {
						if (elem instanceof Integer && fieldTag == null) {
							fieldTag = (Integer) elem;
						}
						else {
							fieldValue = elem.toString();
						}
					}
					String fieldName = null;
					
					switch(fieldTag) {
					case GeneralName.directoryName:
						fieldName = "directoryName";
						break;
					case GeneralName.dNSName:
						fieldName = "dNSName";		
						break;
					case GeneralName.ediPartyName:
						fieldName = "ediPartyName";
						break;
					case GeneralName.iPAddress:
						fieldName = "iPAddress";
						break;
					case GeneralName.otherName:
						fieldName = "otherName";
						break;
					case GeneralName.registeredID:
						fieldName = "registredID";
						break;
					case GeneralName.rfc822Name:
						fieldName = "rfc822name" ;
						break;
					case GeneralName.uniformResourceIdentifier:
						fieldName = "uniformResourceIdentifier";
						break;
					case GeneralName.x400Address:
						fieldName = "x400Address";
						break;
					default:
							//TODO: Baciti exception ovde.
					}
					
					sb.append(fieldName + "=" + fieldValue + ",");
				}
				if (sb.length() != 0) {
					sb.deleteCharAt(sb.length() - 1);
				}
			}
			
			return sb.toString();
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return sb.toString();

	}
	
	public static GeneralNames createIssuerAlternativeName(String[] issuerAltNames) {
		if (issuerAltNames == null || issuerAltNames.length == 0) {
			return null;
		}
		
		
		ArrayList<GeneralName> generalNames = new ArrayList<>();
		
		for(String name: issuerAltNames) {
			name = name.trim();
			String nameType = name.substring(0, name.indexOf('='));
			String nameValue = name.substring(name.indexOf('=') + 1);
			
			int tag = 0;
			switch(nameType) {
			case "directoryName":
				tag = GeneralName.directoryName;
				break;
			case "dNSName":
				tag = GeneralName.dNSName;
				break;
			case "ediPartyName":
				tag = GeneralName.ediPartyName;
				break;
			case "iPAddress":
				tag = GeneralName.iPAddress;
				break;
			case "otherName":
				tag = GeneralName.otherName;
				break;
			case "registredID":
				tag = GeneralName.registeredID;
				break;
			case "rfc822name":
				tag = GeneralName.rfc822Name;
				break;
			case "uniformResourceIdentifier":
				tag = GeneralName.uniformResourceIdentifier;
				break;
			case "x400Address":
				tag = GeneralName.x400Address;
				break;
			default:
					//TODO: Baciti exception ovde.
			}
			
			GeneralName generalName = new GeneralName(tag, nameValue);
			generalNames.add(generalName);
		}
		GeneralName[] array = new GeneralName[generalNames.size()];
		int i = 0;
		for(GeneralName gn:generalNames) {
			array[i++] = gn;
		}
		GeneralNames names = new GeneralNames(array);
		
		return names;
	}
	
	public static void storeKeystore(KeyStore ks, String ksPath, char[] ksPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		
			FileOutputStream output = new FileOutputStream(ksPath);
		
			ks.store(output, ksPassword);
			
			if (output != null) {
				output.close();
			}
	}

	public static boolean isTrusted(KeyStore ks, String clientCertAlias, String baseCertAlias) {
		try {
			
			//Checking if clientCert is baseCert.
			if (clientCertAlias.equals(baseCertAlias)) {
				return true;
			}
			
			else 
				return false;
//			java.security.cert.Certificate baseJavaCert = ks.getCertificate(baseCertAlias);
//			java.security.cert.Certificate clientJavaCert = ks.getCertificate(clientCertAlias);
//			
//			
//			X509CertificateHolder baseCert = new X509CertificateHolder(baseJavaCert.getEncoded());
//			X509CertificateHolder clientCert = new X509CertificateHolder(clientJavaCert.getEncoded());
//			
//			X500Name clientSubject = clientCert.getSubject();
//			X500Name clientIssuer = clientCert.getIssuer();
//			X500Name baseSubject = baseCert.getSubject();
//			
//			//No issuer means that certificate isn't signed.
//			if (clientIssuer == null) {
//				return false;
//			}
//			
//			//This also means that certificate isn't signed.
//			if (clientSubject.toString().equals(clientIssuer.toString())) {
//				return false;
//			}
//			
//			if (clientIssuer.toString().equals(baseSubject.toString())) {
//				return true;
//			}
//			
//			Enumeration<String> aliases = ks.aliases();
//			
//			String issuerAlias = null;
//			
//			while(aliases.hasMoreElements()) {
//				String alias = aliases.nextElement();
//				
//				java.security.cert.Certificate javaCert = ks.getCertificate(alias);
//				X509CertificateHolder cert = new X509CertificateHolder(javaCert.getEncoded());
//				X500Name certSubject = cert.getSubject();
//				
//				if (certSubject.toString().equals(clientIssuer.toString())) {
//					issuerAlias = alias;
//					break;
//				}
//			}
//			
//			if (issuerAlias == null) {
//				return false;
//			}
//			else {
//				return isTrusted(ks, issuerAlias, baseCertAlias);
//			}
//			
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
}
