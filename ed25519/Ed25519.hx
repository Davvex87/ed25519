package ed25519;

import haxe.PosInfos;
import cpp.RawConstPointer;
import haxe.extern.EitherType;
import haxe.Exception;
import cpp.NativeArray;
import haxe.io.Bytes;
import cpp.RawPointer;
import cpp.ConstCharStar;
import cpp.CastCharStar;
import cpp.SizeT;

@:cppInclude("iostream")
class Ed25519
{
	/**
		Creates a cryptographically secure random 32 bit byte array containing a random seed.
	**/
	public static function createSeed():Bytes
	{
		var r = makeUnsignedCharStar(32);
		var b = Bytes.alloc(32);
		if (ExternEd25519.ed25519_create_seed(r) != 0)
			throw new Exception("Failed to create seed");
		untyped __cpp__("memcpy({0}->getBase(), {1}, {2})", b.getData(), r, 32);
		return b;
	}

	/**
		Generates a new keypair containing a 32 bit long public key and a 64 bit long private key from `seed`.
		If `seed` is not provided or is null, a new random seed will be generated.
	**/
	public static function createKeypair(?seed:Bytes):Keypair
	{
		if (seed == null)
			seed = createSeed();

		var pubKey = makeUnsignedCharStar(32);
		var privKey = makeUnsignedCharStar(64);
		var s = bytesToUnsignedCharStar(seed);

		var b = Bytes.alloc(32);
		ExternEd25519.ed25519_create_keypair(pubKey, privKey, s);

		var publicKey = Bytes.alloc(32);
		var privateKey = Bytes.alloc(64);

		untyped __cpp__("memcpy({0}->getBase(), {1}, {2})", publicKey.getData(), pubKey, 32);
		untyped __cpp__("memcpy({0}->getBase(), {1}, {2})", privateKey.getData(), privKey, 64);

		return {
			publicKey: publicKey,
			privateKey: privateKey
		};
	}

	/**
		Signs `message`, could be `Bytes` or `String`, with the public and private keys.
		Returns a new signature used to verify identity.
	**/
	public static function sign(message:EitherType<String, Bytes>, publicKey:Bytes, privateKey:Bytes):Bytes
	{
		var _pubKey = bytesToUnsignedCharStar(publicKey);
		var _privKey = bytesToUnsignedCharStar(privateKey);

		var signature = Bytes.alloc(64);
		var _s = makeUnsignedCharStar(64);

		var _msgData = messageTypeToConstUnsignedCharStar(message);

		ExternEd25519.ed25519_sign(_s, _msgData._msg, _msgData._len, _pubKey, _privKey);

		untyped __cpp__("memcpy({0}->getBase(), {1}, {2})", signature.getData(), _s, 64);


		return signature;
	}

	/**
		Verifies `message` using `signature` and the public key.
	**/
	public static function verify(signature:Bytes, message:EitherType<String, Bytes>, publicKey:Bytes):Bool
	{
		var _s = bytesToUnsignedCharStar(signature);
		var _pubKey = bytesToUnsignedCharStar(publicKey);
		var _msgData = messageTypeToConstUnsignedCharStar(message);

		return ExternEd25519.ed25519_verify(_s, _msgData._msg, _msgData._len, _pubKey) == 1;
	}

	/**
		Returns an brand new keypair from `scalar`.
		Does not overwrite the original `publicKey` and `privateKey` arguments.
	**/
	public static function addScalar(?publicKey:Bytes, ?privateKey:Bytes, ?scalar:Bytes):Null<NullableKeypair>
	{
		if (publicKey == null && privateKey == null)
			return null;

		if (scalar == null)
			scalar = createSeed();

		var _scalar = bytesToUnsignedCharStar(scalar);

		var _newPubKey:UnsignedCharStar = untyped nullptr;
		var _newPrivKey:UnsignedCharStar = untyped nullptr;

		if (publicKey != null)
		{
			_newPubKey = bytesToUnsignedCharStar(publicKey);
			untyped __cpp__("memcpy({0}, {1}->getBase(), {2})", _newPubKey, publicKey.getData(), 32);
		}

		if (privateKey != null)
		{
			_newPrivKey = bytesToUnsignedCharStar(privateKey);
			untyped __cpp__("memcpy({0}, {1}->getBase(), {2})", _newPrivKey, privateKey.getData(), 64);
		}

		ExternEd25519.ed25519_add_scalar(_newPubKey, _newPrivKey, _scalar);

		var newPublicKey:Null<Bytes> = null;
		var newPrivateKey:Null<Bytes> = null;

		if (publicKey != null)
		{
			newPublicKey = Bytes.alloc(32);
			untyped __cpp__("memcpy({0}->getBase(), {1}, {2})", newPublicKey.getData(), _newPubKey, 32);
		}

		if (privateKey != null)
		{
			newPrivateKey = Bytes.alloc(64);
			untyped __cpp__("memcpy({0}->getBase(), {1}, {2})", newPrivateKey.getData(), _newPrivKey, 64);
		}

		return {
			publicKey: newPublicKey,
			privateKey: newPrivateKey
		};
	}

	/**
		Exchanges a shared secret given a remote public key and our local private key.
	**/
	public static function keyExchange(publicKey:Bytes, privateKey:Bytes):Bytes
	{
		var _pubKey = bytesToUnsignedCharStar(publicKey);
		var _privKey = bytesToUnsignedCharStar(privateKey);

		var sharedSecret = Bytes.alloc(32);
		var _secr = makeUnsignedCharStar(32);

		ExternEd25519.ed25519_key_exchange(_secr, _pubKey, _privKey);

		untyped __cpp__("memcpy({0}->getBase(), {1}, {2})", sharedSecret.getData(), _secr, 32);

		return sharedSecret;
	}

	/*
	 * Utility functions
	 */

	static inline function makeUnsignedCharStar(s:Int):UnsignedCharStar
		return cast NativeArray.getBase(NativeArray.create(s)).getBase();

	static inline function bytesToUnsignedCharStar(b:Bytes):UnsignedCharStar
		return cast NativeArray.getBase(b.getData()).getBase();

	static inline function messageTypeToConstUnsignedCharStar(message:EitherType<String, Bytes>, ?pos:PosInfos):{_msg:ConstUnsignedCharStar, _len:Int}
	{
		var _msg:ConstUnsignedCharStar;
		var _len:Int;

		if (message is String)
		{
			_msg = cast untyped __cpp__ ("{0}.__s", (message : String));
			_len = (message : String).length;
		}
		else if (message is Bytes)
		{
			_msg = bytesToUnsignedCharStar(cast message);
			_len = (message : Bytes).length;
		}
		else 
			throw new Exception("Argument 'message' must be of either type String or Bytes");

		return {
			_msg: _msg,
			_len: _len
		}
	}
}

typedef Keypair = {
	var publicKey:Bytes;
	var privateKey:Bytes;
}

typedef NullableKeypair = {
	var ?publicKey:Bytes;
	var ?privateKey:Bytes;
}

@:keep
@:buildXml('
	<files id="haxe">
		<compilerflag value="-I${haxelib:ed25519}/dependencies/ed25519/src"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/add_scalar.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/fe.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/ge.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/key_exchange.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/keypair.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/sc.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/seed.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/sha512.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/sign.c"/>
		<file name="${haxelib:ed25519}/dependencies/ed25519/src/verify.c"/>
	</files>
	<target id="haxe">
		<section if="windows">
			<lib name="Advapi32.lib" />
		</section>
	</target>
')
@:include('ed25519.h')
extern class ExternEd25519
{
	@:native("ed25519_create_seed")
	static function ed25519_create_seed(seed:UnsignedCharStar):Int;

	@:native("ed25519_create_keypair")
	static function ed25519_create_keypair(public_key:UnsignedCharStar, private_key:UnsignedCharStar, seed:ConstUnsignedCharStar):Void;

	@:native("ed25519_sign")
	static function ed25519_sign(signature:UnsignedCharStar, message:ConstUnsignedCharStar, message_len:SizeT, public_key:ConstUnsignedCharStar, private_key:ConstUnsignedCharStar):Void;

	@:native("ed25519_verify")
	static function ed25519_verify(signature:ConstUnsignedCharStar, message:ConstUnsignedCharStar, message_len:SizeT, public_key:ConstUnsignedCharStar):Int;

	@:native("ed25519_add_scalar")
	static function ed25519_add_scalar(public_key:UnsignedCharStar, private_key:UnsignedCharStar, scalar:ConstUnsignedCharStar):Void;

	@:native("ed25519_key_exchange")
	static function ed25519_key_exchange(shared_secret:UnsignedCharStar, public_key:ConstUnsignedCharStar, private_key:ConstUnsignedCharStar):Void;
}

private typedef UnsignedCharStar = RawPointer<cpp.UInt8>;
private typedef ConstUnsignedCharStar = RawConstPointer<cpp.UInt8>;