const crypto = require("crypto");
const PublicKey = require("./publicKey").PublicKey;
const der = require("./utils/der");

class PrivateKey {
    constructor() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("ml-dsa-65");
        this.nodePrivateKey = privateKey;
        this.nodePublicKey = publicKey;
    };

    publicKey () {
        let pub = new PublicKey();
        pub.nodePublicKey = this.nodePublicKey;
        return pub;
    };

    toString () {
        return this.nodePrivateKey.export({ format: "pem", type: "pkcs8" });
    };

    toHexString () {
        return this.nodePrivateKey.export({ format: "der", type: "pkcs8" }).toString("hex");
    };

    toDer () {
        return this.nodePrivateKey.export({ format: "der", type: "pkcs8" });
    }

    toPem () {
        return this.nodePrivateKey.export({ format: "pem", type: "pkcs8" });
    };

    static fromPem (string) {
        let priv = crypto.createPrivateKey(string);
        let pub = crypto.createPublicKey(priv);
        let instance = new PrivateKey();
        instance.nodePrivateKey = priv;
        instance.nodePublicKey = pub;
        return instance;
    };

    static fromDer(string) {
        let priv = crypto.createPrivateKey({
            key: string,
            format: "der",
            type: "pkcs8"
        });
        let pub = crypto.createPublicKey(priv);
        let instance = new PrivateKey();
        instance.nodePrivateKey = priv;
        instance.nodePublicKey = pub;
        return instance;
    };

    static fromString (string) {
        return this.fromPem(string);
    };

    static fromHexString(string) {
        return this.fromDer(Buffer.from(string, "hex"));
    };
};


exports.PrivateKey = PrivateKey;
