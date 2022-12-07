const fs = require('fs')
const { getPrivateAndPublicKeyFromPassphrase } = require('@liskhq/lisk-cryptography');
const { Mnemonic } = require('@liskhq/lisk-passphrase');
const sodium = require('sodium-native');
const net = require('net');

const settingsPath = "./settings.json";
const wireguardPath = "/etc/wireguard";

let pluginPackage = {};
if (fs.existsSync(settingsPath)) { pluginPackage = require(settingsPath); }

const idnttyEndtpoint =  pluginPackage.idnttyEndtpoint || "wss://tn-alpha.idntty.org:8090/ws";
const privateSubnet = pluginPackage.privateSubnet || "10.1.0.1/20";

const publicPort = pluginPackage.publicPort || 2049;
const passPhrase = process.env.IDNTTYPASSPHARESE || Mnemonic.generateMnemonic();
const interface = pluginPackage.interface || "idntty";

let idnttyKeys = getPrivateAndPublicKeyFromPassphrase(passPhrase);
const PrivateKey = idnttyKeys.privateKey;
const publicKey = idnttyKeys.publicKey.toString('hex');

const PrivateKeyX25519 = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES);
sodium.crypto_sign_ed25519_sk_to_curve25519(PrivateKeyX25519, PrivateKey);

const wireguardSettings =  `
[Interface]
Address = ${privateSubnet}
ListenPort = ${publicPort}
PrivateKey = ${PrivateKeyX25519.toString('base64')}

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i idntty -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE # Add forwarding when VPN is started
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i idntty -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE # Remove forwarding when VPN is shutdown
`


console.log("Universal phrase for generating private keys, please keep it safe:", passPhrase);

if (!fs.existsSync(wireguardPath + "/" + interface + ".conf")) {
    console.log("Wireguard settings updated at:", wireguardPath + "/" + interface + ".conf");
    fs.writeFileSync(wireguardPath + "/" + interface + ".conf", wireguardSettings);
} else {
    console.log("Please, update your interface seetings with data below:");
    console.log("---------------------------------------------------------------------");
    console.log(wireguardSettings)
}

if (!fs.existsSync(settingsPath)) {
    const client = net.connect({port: 443, host:"idntty.org"}, () => {
        pluginPackage.idnttyEndtpoint  = idnttyEndtpoint;
        pluginPackage.idnttyPublicKey  = publicKey;
        pluginPackage.interface  = interface;
        pluginPackage.privateSubnet = privateSubnet;
        pluginPackage.publicAddress = client.localAddress;
        pluginPackage.publicPort = publicPort;
        pluginPackage.county = "Default";
        pluginPackage.region = "Default";
        pluginPackage.dns = ['1.1.1.1','9.9.9.9'];
        pluginPackage.clients = [];  

        console.log("IDNTTY settings updated at:", settingsPath);
        fs.writeFileSync(settingsPath, JSON.stringify(pluginPackage, null, 4));
      });
}

