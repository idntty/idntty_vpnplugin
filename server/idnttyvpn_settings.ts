const fs = require('fs')
const Netmask = require('netmask').Netmask;
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
const publicPort = pluginPackage.publicPort || 137;
const passPhrase = process.env.IDNTTYPASSPHARESE || Mnemonic.generateMnemonic();
const interface = pluginPackage.interface || "idntty";

const PrivateKey = getPrivateAndPublicKeyFromPassphrase(passPhrase).privateKey;
const PrivateKeyX25519 = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES);
sodium.crypto_sign_ed25519_sk_to_curve25519(PrivateKeyX25519, PrivateKey);

const wireguardSettings =  `
[Interface]
Address = ${privateSubnet}
ListenPort = ${publicPort}
PrivateKey = ${PrivateKeyX25519.toString('base64')}

ufw route allow in on ${interface} out on eth0
PostUp = iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
PostUp = ip6tables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
PreDown = ufw route delete allow in on ${interface} out on eth0
PreDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PreDown = ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
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
        pluginPackage.interface  = interface;
        pluginPackage.privateSubnet = privateSubnet;
        pluginPackage.publicAddress = client.localAddress;
        pluginPackage.publicPort = publicPort;
        pluginPackage.clients = [];  

        console.log("IDNTTY settings updated at:", settingsPath);
        fs.writeFileSync(settingsPath, JSON.stringify(pluginPackage, null, 4));
      });
}

