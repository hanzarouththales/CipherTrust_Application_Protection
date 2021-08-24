/**
* Sample code is provided for educational purposes.
* No warranty of any kind, either expressed or implied by fact or law.
* Use of this item is not restricted by copyright or license terms.
*/
// Standard JCE classes. 
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;

import com.ingrian.security.nae.IngrianProvider;
// CADP JCE specific classes.
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESecureRandom;
import com.ingrian.security.nae.NAESession;
/**
 * This sample shows how to encrypt and decrypt file using CADP JCE.
 */
public class FileEncryptionSampleTest {
        public static void main( String[] args ) throws Exception
    {
	if (args.length != 7)
        {
            System.err.println
			// changes here
		("Usage: java FileEncryptionSample user password keyname fileToEncrypt encryptedFile decryptedFile encrypt/decrypt");
            System.exit(-1);
	} 
        String username  = args[0];
        String password  = args[1];
        String keyName   = args[2];
	String srcName   = args[3];
	String dstName   = args[4];
	String decrName  = args[5];
	//changes here
	String encOrdec = args [6];
	
	// how many bytes of data to read from the input stream - can be any size
	int BUFSIZE = 512;

	// add Ingrian provider to the list of JCE providers
	Security.addProvider(new IngrianProvider());

	// get the list of all registered JCE providers
	Provider[] providers = Security.getProviders();
	for (Provider provider : providers) {
		System.out.println(provider.getInfo());
	}

		// create NAE Session: pass in Key Manager user name and password
    NAESession session=null;


	try {
		
		
		// changes here
		if (encOrdec.equalsIgnoreCase("encrypt")) {


	// create NAE Session: pass in Key Manager user name and password
    
	session=null;
		
		
		session  = 
				NAESession.getSession(username, password.toCharArray());
	    // Get SecretKey (just a handle to it, key data does not leave the Key Manager
	    NAEKey key = NAEKey.getSecretKey(keyName, session);
	    
	    // get IV
	    //NAESecureRandom rng = new NAESecureRandom (session);
	
	    //byte[] iv = new byte[16];
	    //rng.nextBytes(iv);
	    //IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    
		// changes here
		byte[] inbuf = new byte[BUFSIZE];
		
		
		
	    // get a cipher
	    Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");

	    // initialize cipher to encrypt.
	    encryptCipher.init(Cipher.ENCRYPT_MODE, key);

	    // create CipherInputStream that will read in data from file and encrypt it
	    CipherInputStream cis = new CipherInputStream(new FileInputStream(srcName), encryptCipher);
	    FileOutputStream fos  = new FileOutputStream(dstName);
	    
	    // Read the file as blocks of data
	    
	    for ( int inlen = 0; (inlen = cis.read(inbuf)) != -1;  ) {
		fos.write( inbuf, 0, inlen);
	    }

	    System.out.println("Done encrypting file.  Closing files");
	    cis.close();
	    fos.close();

		session.closeSession();
		
		
		// changes here
		} else {

	// create NAE Session: pass in Key Manager user name and password
    session=null;
		
		
		session  = 
				NAESession.getSession(username, password.toCharArray());
	    // Get SecretKey (just a handle to it, key data does not leave the Key Manager
	    NAEKey key = NAEKey.getSecretKey(keyName, session);
	    
	    // get IV
	   // NAESecureRandom rng = new NAESecureRandom (session);
	
	    //byte[] iv = new byte[16];
	    //rng.nextBytes(iv);
	    //IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    
		// changes here
		byte[] inbuf = new byte[BUFSIZE];
		
		
		
		// get a cipher
	    Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
	    // initialize cipher to decrypt.
	    decryptCipher.init(Cipher.DECRYPT_MODE, key);

	    // create CipherInputStream that will read in data from file and decrypt it
		// changes here
	    CipherInputStream cis = new CipherInputStream(new FileInputStream(dstName), decryptCipher);
	    // changes here
		System.out.println("Name of file to decrypt: " + dstName + ".");
		// changes here
		FileOutputStream fos = new FileOutputStream(decrName);

		System.out.println("Start reading file for decryption...");
		// changes here
	    for ( int inlen = 0; (inlen = cis.read(inbuf)) != -1;  ) {
		System.out.println("Reading and writing decrypted blocks to file...");	
		// changes here
		fos.write( inbuf, 0, inlen);
		System.out.println("Wrote a block...");
	    }
	    System.out.println("Done decrypting file.  Closing files");
		// changes here
	    cis.close();
		// changes here
	    fos.close();

		
		}
	} catch (Exception e) {
	    System.out.println("The Cause is " + e.getMessage() + ".");
	    throw e;
	} finally{
		if(session!=null) {
			session.closeSession();
		}
	}
    }
}
