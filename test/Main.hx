package;

import haxe.Timer;
import haxe.Log;
import haxe.PosInfos;
import haxe.io.Bytes;
import ed25519.Ed25519;

class Main
{
	static function main()
	{
		final message = "Hello, world!";

		// create a random seed and a random keypair out of that seed
		var seed = Ed25519.createSeed();
		printBytes(seed);

		var keypair = Ed25519.createKeypair(seed);

		printBytes(keypair.publicKey);
		printBytes(keypair.privateKey);

		// create signature on the message with the keypair
		var signature = Ed25519.sign(message, keypair.publicKey, keypair.privateKey);

		// verify the signature
		if (Ed25519.verify(signature, message, keypair.publicKey))
			trace("Valid signature");
		else 
			trace("Invalid signature");

		// create scalar and create a new keypair with it
		var scalar = Ed25519.createSeed();
		var newKeypair = Ed25519.addScalar(keypair.publicKey, keypair.privateKey, scalar);

		// create signature with the new keypair
		var newSignature = Ed25519.sign(message, newKeypair.publicKey, newKeypair.privateKey);

		// verify the signature with the new keypair
		if (Ed25519.verify(newSignature, message, newKeypair.publicKey))
			trace("Valid signature with new keypair");
		else 
			trace("Invalid signature with new keypair");

		// make a slight adjustment and verify again
		newSignature.set(44, newSignature.get(44) ^ 0x10);
		if (Ed25519.verify(newSignature, message, newKeypair.publicKey))
			trace("Did not detect signature change");
		else 
			trace("correctly detected signature change");

		// generate two keypairs for testing key exchange
		var myKeypair = Ed25519.createKeypair();
		var otherKeypair = Ed25519.createKeypair();

		// create two shared secrets - from both perspectives - and check if they're equal
		var mySharedSecret = Ed25519.keyExchange(otherKeypair.publicKey, myKeypair.privateKey);
		var otherSharedSecret = Ed25519.keyExchange(myKeypair.publicKey, otherKeypair.privateKey);

		if (mySharedSecret.compare(otherSharedSecret) == 0)
			trace("Key exchange was correct");
		else 
			trace("key exchange was incorrect");

		// Test performance
		var perfTestStart = Timer.stamp();

		trace("Testing seed generation performance");
		Timer.measure(() -> {
			for (i in 0...10000)
				Ed25519.createKeypair(seed);
		});

		trace("Testing sign performance");
		Timer.measure(() -> {
			for (i in 0...10000)
				Ed25519.sign(message, keypair.publicKey, keypair.privateKey);
		});

		trace("Testing verify performance");
		Timer.measure(() -> {
			for (i in 0...10000)
				Ed25519.verify(signature, message, keypair.publicKey);
		});

		trace("Testing keypair scalar addition performance");
		Timer.measure(() -> {
			for (i in 0...10000)
				Ed25519.addScalar(keypair.publicKey, keypair.privateKey, scalar);
		});

		trace("Testing public key scalar addition performance");
		Timer.measure(() -> {
			for (i in 0...10000)
				Ed25519.addScalar(keypair.publicKey, null, scalar);
		});

		trace("Testing key exchange performance");
		Timer.measure(() -> {
			for (i in 0...10000)
				Ed25519.keyExchange(otherKeypair.publicKey, myKeypair.privateKey);
		});

		trace('Performance tests complete! Took ${Timer.stamp() - perfTestStart} seconds');
	}

	static function printBytes(bytes:Bytes, ?pos:PosInfos)
	{
		final buf = new StringBuf();
		for (i in 0...bytes.length)
		{
			buf.add(Std.string(bytes.get(i)));
			if (i < bytes.length-1)
				buf.add(" ");
		}
		Log.trace(buf, pos);
	}
}