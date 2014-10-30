// Copyright (c) 2014 Tom Zhou<iwebpp@gmail.com>


package com.iwebpp.crypto.tests;

import java.io.UnsupportedEncodingException;
import com.iwebpp.crypto.TweetNacl;

public final class TweetNaclTest {
	private static final String TAG = "TweetNaclTest";

	private boolean testBox() throws UnsupportedEncodingException {
		// keypair A
		byte [] ska = new byte[32]; for (int i = 0; i < 32; i ++) ska[i] = 0;
		TweetNacl.Box.KeyPair ka = TweetNacl.Box.keyPair_fromSecretKey(ska);
		
		String skat = "";
		for (int i = 0; i < ka.getSecretKey().length; i ++)
			skat += " "+ka.getSecretKey()[i];
		System.out.println("skat: "+skat);
		
		String pkat = "";
		for (int i = 0; i < ka.getPublicKey().length; i ++)
			pkat += " "+ka.getPublicKey()[i];
		System.out.println("pkat: "+pkat);
		
		// keypair B
		byte [] skb = new byte[32]; for (int i = 0; i < 32; i ++) skb[i] = 1;
		TweetNacl.Box.KeyPair kb = TweetNacl.Box.keyPair_fromSecretKey(skb);
		
		String skbt = "";
		for (int i = 0; i < kb.getSecretKey().length; i ++)
			skbt += " "+kb.getSecretKey()[i];
		System.out.println("skbt: "+skbt);
		
		String pkbt = "";
		for (int i = 0; i < kb.getPublicKey().length; i ++)
			pkbt += " "+kb.getPublicKey()[i];
		System.out.println("pkbt: "+pkbt);
		
		// peer A -> B
		TweetNacl.Box pab = new TweetNacl.Box(kb.getPublicKey(), ka.getSecretKey(), 0);

		// peer B -> A
		TweetNacl.Box pba = new TweetNacl.Box(ka.getPublicKey(), kb.getSecretKey(), 0);

		// messages
		String m0 = "Helloword, TweetNacl...";
		
		// cipher A -> B
		byte [] cab = pab.box(m0.getBytes("utf-8"));
		String cabt = "";
		for (int i = 0; i < cab.length; i ++)
			cabt += " "+cab[i];
		System.out.println("cabt: "+cabt);
		
		byte [] mba = pba.open(cab);
		String mbat = "";
		for (int i = 0; i < mba.length; i ++)
			mbat += " "+mba[i];
		System.out.println("mbat: "+mbat);
		
		String nm0 = new String(mba, "utf-8");
		if (nm0.equals(m0)) {
			System.out.println("box/open string success @" + m0);
		} else {
			System.out.println("box/open string failed @" + m0 + " / " + nm0);
		}
		
		// cipher B -> A
        byte [] b0 = new byte[6];
        
        System.out.println("box@" + System.currentTimeMillis());
        byte [] cba = pba.box(b0);
		byte [] mab = pab.open(cba);
        System.out.println("open@" + System.currentTimeMillis());

		if (b0.length == mab.length) {
			int rc = 0;
			
			for (int i = 0; i < b0.length; i ++)
				if (!(b0[i] == mab[i])) {
					rc = -1;
					System.out.println("box/open binary failed @" + b0[i] + " / " + mab[i]);
				}

			if (rc == 0)
				System.out.println("box/open binary success @" + b0);
		} else {
			System.out.println("box/open binary failed @" + b0 + " / " + mab);
		}

		return true;
	}
	
	private boolean testSecretBox() throws UnsupportedEncodingException {
		// shared key
		byte [] shk = new byte[TweetNacl.SecretBox.keyLength];
		for (int i = 0; i < shk.length; i ++)
			shk[i] = 0x66;

		// peer A -> B
		TweetNacl.SecretBox pab = new TweetNacl.SecretBox(shk, 0x68);

		// peer B -> A
		TweetNacl.SecretBox pba = new TweetNacl.SecretBox(shk, 0x68);

		// messages
		String m0 = "Helloword, TweetNacl...";
		
		// cipher A -> B
		System.out.println("streess on secret box@"+m0);
		
		for (int t = 0; t < 19; t ++, m0 += m0) {
			byte [] mb0 = m0.getBytes("utf-8");
			
			System.out.println("\n\n\tstreess/"+(mb0.length/1000.0) +"kB: " + t + " times");

			///String mb0t = "mb0/"+mb0.length + ": ";
			//for (int i = 0; i < mb0.length; i ++)
			///	mb0t += " "+mb0[i];
			///System.out.println(mb0t);

			System.out.println("secret box ...@" + System.currentTimeMillis());
			byte [] cab = pab.box(mb0);
			System.out.println("... secret box@" + System.currentTimeMillis());

			///String cabt = "cab/"+cab.length + ": ";
			///for (int i = 0; i < cab.length; i ++)
			///	cabt += " "+cab[i];
			///System.out.println(cabt);

			System.out.println("\nsecret box open ...@" + System.currentTimeMillis());
			byte [] mba = pba.open(cab);
			System.out.println("... secret box open@" + System.currentTimeMillis());

			///String mbat = "mba/"+mba.length + ": ";
			///for (int i = 0; i < mba.length; i ++)
			///	mbat += " "+mba[i];
			///System.out.println(mbat);

			String nm0 = new String(mba, "utf-8");
			if (nm0.equals(m0)) {
				System.out.println("\tsecret box/open succes");
			} else {
				System.out.println("\tsecret box/open failed @" + m0 + " / " + nm0);
				return false;
			}
		}
		
		return true;
	}
	
	private boolean testSign() throws UnsupportedEncodingException {
		// keypair A
		TweetNacl.Signature.KeyPair ka = TweetNacl.Signature.keyPair();

		// keypair B
		TweetNacl.Signature.KeyPair kb = TweetNacl.Signature.keyPair();

		// peer A -> B
		TweetNacl.Signature pab = new TweetNacl.Signature(kb.getPublicKey(), ka.getSecretKey());

		// peer B -> A
		TweetNacl.Signature pba = new TweetNacl.Signature(ka.getPublicKey(), kb.getSecretKey());

		// messages
		String m0 = "Helloword, TweetNacl...";

		// signature A -> B
        System.out.println("sign...@" + System.currentTimeMillis());
		byte [] sab = pab.sign(m0.getBytes("utf-8"));
        System.out.println("...sign@" + System.currentTimeMillis());

		String sgt = "sign@"+m0 + ": ";
		for (int i = 0; i < TweetNacl.Signature.signatureLength; i ++)
			sgt += " "+sab[i];
		System.out.println(sgt);
		
        System.out.println("verify...@" + System.currentTimeMillis());
		byte [] oba = pba.open(sab);
        System.out.println("...verify@" + System.currentTimeMillis());

		if (oba == null) {
			System.out.println("verify failed @" + m0);
		} else {
			String nm0 = new String(oba, "utf-8");
			if (nm0.equals(m0)) {
				System.out.println("sign success @" + m0);
			} else {
				System.out.println("sign failed @" + m0 + " / " + nm0);
			}
		}
		
		return true;
	}
	
	/*
	 * SHA-512
	 * */
	private boolean testHash() throws UnsupportedEncodingException {
		String m0 = "Helloword, TweetNacl...";
		
        System.out.println("sha512...@" + System.currentTimeMillis());
		byte [] hash = TweetNacl.Hash.sha512(m0);
        System.out.println("...sha512@" + System.currentTimeMillis());

		String hst = "sha512@"+m0 + ": ";
		for (int i = 0; i < hash.length; i ++)
			hst += " "+hash[i];
		System.out.println(hst);
		
		return true;
	}
	
	/*
	 * bench test using tweetnacl.c, tweetnacl.js result
	 * */
	private boolean testBench() {
		
		return true;
	}
	
	public static int main() {
		final TweetNaclTest tst = new TweetNaclTest();
		
		(new Thread(new Runnable() {
			public void run() {
				System.out.println("start test");

				try {
					tst.testSign();
					tst.testSecretBox();
					tst.testBox();
					tst.testHash();
					
					///tst.testBench();
				} catch (UnsupportedEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}			    
			}
		})).start();

		return 0;
	}

}
