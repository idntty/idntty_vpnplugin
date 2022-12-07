const serverPackage = require('./settings.json');
const fs = require('fs')
const { codec } = require('lisk-sdk');
const { exec } = require("child_process");
const { Wg } = require('wireguard-wrapper');
const { apiClient } = require('@liskhq/lisk-client');
const Netmask = require('netmask').Netmask;
const { getPrivateAndPublicKeyFromPassphrase } = require('@liskhq/lisk-cryptography');

var sodium = require('sodium-native');
var http = require('http');

const privateKey = process.env.PRIVATEKEY;

class IdnttyVPNServer {

    passPhrase = null;
    idnttyPublicKey = null;
    idnttyPrivateKey = null;

    idnttyEndtpoint = null;
    idnttyNodeClient = null;
    idnttyNodePublicKey = null;
    idnttyNodeHeardbeat = 0;
        
    interface = null;
    publicKey = null;    
    publicAddress = null;
    publicPort = null;
    privateSubnet = null;
    county = "Default";
    region = "Default";
    
    vpnHeardbeat = 0;
        
    peers = [];

    constructor() {

        if (process.env.IDNTTYPASSPHARESE == null){
            throw new Error('DEBUG: The server cannot start without the IDNTTYPASSPHARESE environment variable.');
        } else {
            let idnttyKeys = getPrivateAndPublicKeyFromPassphrase(process.env.IDNTTYPASSPHARESE);
            if (Buffer.compare(Buffer.from(serverPackage.idnttyPublicKey, 'hex'), idnttyKeys.publicKey) == 0) {
                this.idnttyPublicKey = idnttyKeys.publicKey;
                this.idnttyPrivateKey = idnttyKeys.privateKey;
            } else {
                throw new Error('DEBUG: Keys generated from IDNTTYPASSPHARESE and keys from settings file do not match:' + serverPackage.idnttyPublicKey + " vs " + idnttyKeys.publicKey.toString('hex'));
            }
        }

        
        this.idnttyEndtpoint = serverPackage.idnttyEndtpoint;        

        this.interface = serverPackage.interface;
        this.publicKey = serverPackage.publicKey;
        this.publicAddress = serverPackage.publicAddress;
        this.publicPort = serverPackage.publicPort;
        this.privateSubnet = serverPackage.privateSubnet;
        this.defaultPeers = serverPackage.clients;
        this.county = serverPackage.county;
        this.region = serverPackage.region;        
    }


    async _load() {
        apiClient.createWSClient(this.idnttyEndtpoint).then(async _client => {
            this.idnttyNodeClient = _client;
            
            this._subscribeEvents();
            this._tunnelOnline();
        });
    }

    async _unload() {}

    async _tunnelOnline() {
        let _tunnel = {
            publicKey: this.idnttyPublicKey.toString('hex'),
            serverAddress: this.publicAddress, 
            serverPort: this.publicPort,
            serverSubnet: this.privateSubnet,            
            county: this.county,
            region: this.region
        }

        this.idnttyNodeClient.invoke('idnttyvpn:tunnelAdd',_tunnel)
        .then( async _idnttyNode => {
            console.log("DEBUG:", "_tunnelOnline");
            this.idnttyNodePublicKey = _idnttyNode.publicKey;
            this._tunnelHeartbeat();
        });
    }

    async _tunnelStatus() {
        const vpnPeers = await this._getVPNPeers();
        let _tunnel = {
            publicKey: this.idnttyPublicKey.toString('hex'),
            transferRx: 0,
            transferTx: 0,
            peers:[]
        }        

        this.peers.forEach(idnntyPeer => {
            vpnPeers.forEach(wgPeer => {
                if (idnntyPeer.wgPublicKey == wgPeer.wgPublicKey){

                    let peer = {
                        publicKey:idnntyPeer.publicKey, 
                        transferRx: wgPeer.transferRx - idnntyPeer.transferRx, 
                        transferTx: wgPeer.transferTx - idnntyPeer.transferTx, 
                        address: wgPeer.allowedIps,
                        latestHandshake: wgPeer.latestHandshake
                    }

                    _tunnel.transferRx = _tunnel.transferRx + peer.transferRx;
                    _tunnel.transferTx = _tunnel.transferTx + peer.transferTx;

                    _tunnel.peers.push(peer);
                    
                    idnntyPeer.transferRx = wgPeer.transferRx;
                    idnntyPeer.transferTx = wgPeer.transferTx;
                    idnntyPeer.allowedIps = wgPeer.allowedIps;
                }
            });
        });
 
        this.idnttyNodeClient.invoke('idnttyvpn:tunnelUpdateStatus', _tunnel)
        .then( async _idnttyNode => {
            console.log("DEBUG:", "_tunnelStatus");
        });   
    }

    async _tunnelHeartbeat() {        
        let idnttyNodeHeartbeat = setInterval(async () => {
            console.log("DEBUG:", "_tunnelHeartbeat",this.idnttyNodeClient._channel.isAlive,  this.idnttyNodeHeardbeat);            
            if (!this.idnttyNodeClient._channel.isAlive && this.idnttyNodeHeardbeat < 10) {
                this.idnttyNodeHeardbeat++;
                try {
                    this.idnttyNodeClient = await apiClient.createWSClient(this.idnttyEndtpoint);
                    this._subscribeEvents();
                } catch (error) {
                    console.error("IDNTTY Node Connection error:", error.message);
                }
            } else if (!this.idnttyNodeClient._channel.isAlive && this.idnttyNodeHeardbeat == 10) { //10 tries to restore connection 
                clearInterval(idnttyNodeHeartbeat);
            } else {
                this.idnttyNodeHeardbeat = 0;
            }
          }, 30000); //30 sec between tries
    }

    async _peerAdd(clientPublicKey) {
        //get ip for new peer
        let peerIp = this._calculatePeerIP();
        if (peerIp == null) {return false;}
        
        console.log("peerIp:", peerIp);

        peerIp = peerIp.concat("/32");

        //convert from idntty PK to WG PK
        let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
        sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, Buffer.from(clientPublicKey, 'hex'));
        let wgPublicKey = x25519_pk.toString('Base64');



         exec(`sudo wg set ${this.interface} peer ${wgPublicKey} allowed-ips ${peerIp}`, (error, stdout, stderr) => {
             if (error || stderr) {
                console.log("DEBUG:", "_peerAdd error", error, stderr);
                return false; 
            }

            let _peer = {
                tunnelPublicKey: this.idnttyPublicKey.toString('hex'),
                publicKey: clientPublicKey,
                state: 1,
                address: peerIp
            };
            this.idnttyNodeClient.invoke('idnttyvpn:peerConfirm', _peer);        
            console.log("DEBUG:", "_peerAdd", clientPublicKey);

            let peer = {
                publicKey: clientPublicKey,
                wgPublicKey: x25519_pk.toString('Base64'),
                endpoint: null,
                allowedIps: peerIp,
                latestHandshake: null,
                transferRx: 0,
                transferTx: 0,
            };
            this.peers.push(peer);

            return true;
         });

    }

    async _peerRemove(clientPublicKey) {
        //convert from idntty PK to WG PK
        let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
        sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, Buffer.from(clientPublicKey, 'hex'));  
        let wgPublicKey = x25519_pk.toString('Base64');

        exec(`sudo wg set ${this.interface} peer ${wgPublicKey} remove`, (error, stdout, stderr) => {
            if (error || stderr) { 
                console.log("DEBUG:", "_peerRemove error", error, stderr);
                return false; 
            }            
            console.log("DEBUG:", "_peerRemove", clientPublicKey);
            for( var i = 0; i < this.peers.length; i++){ if ( this.peers[i].publicKey === clientPublicKey) { this.peers.splice(i, 1); } }
            return true;
        });
    }

    /* Utils */
    _calculatePeerIP() {
        let _privateSubnet = new Netmask(this.privateSubnet);

        let peersIP = [];
        this.peers.forEach((_peer) => {            
            let peerIP = _peer.allowedIps[0].substring(0, _peer.allowedIps[0].indexOf("/"));            
            let peerIPnumber = peerIP.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
            peersIP.push(peerIPnumber);
        });

        if (peersIP.length >= _privateSubnet.size) { return null; }

        let IPnumber = _privateSubnet.first.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
        for (let i = 1; i<_privateSubnet.size; i++) { //first reserved for the gateway
            IPnumber = IPnumber + i;
            if (!peersIP.includes(IPnumber)) { return ( (IPnumber>>>24) +'.' + (IPnumber>>16 & 255) +'.' + (IPnumber>>8 & 255) +'.' + (IPnumber & 255) ); }
        }

        return null;
    }

    async _getVPNPeers(){
        let peers = [];
        const interfaceName = this.interface;

        await Wg.show(interfaceName).then(async function(_interface) {            
            Object.keys(_interface[interfaceName]['_peers']).forEach((_peer) => {
                let peer = {
                    wgPublicKey: _peer,
                    endpoint: _interface[interfaceName]['_peers'][_peer]["_endpoint"],
                    allowedIps: _interface[interfaceName]['_peers'][_peer]["_allowedIps"][0],
                    latestHandshake: _interface[interfaceName]['_peers'][_peer]["_latestHandshake"],
                    transferRx: _interface[interfaceName]['_peers'][_peer]["_transferRx"],
                    transferTx: _interface[interfaceName]['_peers'][_peer]["_transferTx"],
                };                
                peers.push(peer);
            });
        });
        console.log("DEBUG:", "_getVPNPeers");
        return peers;
    }

    _subscribeEvents() {
        this.idnttyNodeClient.subscribe('idnttyvpn:peerAdd', (_peer) => {
            this._peerAdd(_peer.peerPublicKey);
        });
        this.idnttyNodeClient.subscribe('idnttyvpn:peerRemove', (_peer) => {
            this._peerRemove(_peer.peerPublicKey);                
        });            
        this.idnttyNodeClient.subscribe('app:block:new', (_block) => {
            this._tunnelStatus();
        });
    }

    /* depricated */

    load() {        
        apiClient.createWSClient(this.idnttyEndtpoint).then(async _client => {
            this.idnttyNodeClient = _client;            
            this.online();            

            this.idnttyNodeClient.subscribe('idnttyvpn:peerAdd', (_peer) => {
                console.log("peer to add:", _peer);
                let allowedIP = this.calculateNextIp();
	            let addpeerresult = this.addVPNPeer(_peer.peerPublicKey, allowedIP.concat("/32"));
            });

            this.idnttyNodeClient.subscribe('idnttyvpn:peerRemove', (_peer) => {
                console.log("peer to remove:", _peer);
                let addpeerresult = this.removeVPNPeer(_peer.peerPublicKey);                
            });
            
            this.idnttyNodeClient.subscribe('app:block:new', (_block) => { //Ping every 10 blocks                
                //this.vpnHeardbeat++;
                //if (this.vpnHeardbeat % 10 == 0) {
                    this.ping();
                //    this.vpnHeardbeat = 0;
                //}                
            });
            
            this.updateVPNPeers();            
            this.idnttyNodeHeartbeat();
        });
    }

    idnttyNodeHeartbeat() {
        let idnttyNodeHeartbeat = setInterval(async () => {
            console.log("alive:", this.idnttyNodeHeardbeat, this.idnttyNodeClient._channel.isAlive);

            if (!this.idnttyNodeClient._channel.isAlive && this.idnttyNodeHeardbeat < 10) {
                this.idnttyNodeHeardbeat++;
                try {
                    this.idnttyNodeClient = await apiClient.createWSClient(this.idnttyEndtpoint);                    
                } catch (error) {
                    console.error("IDNTTY Node Connection error:", error.message);
                }
            } else if (!this.idnttyNodeClient._channel.isAlive && this.idnttyNodeHeardbeat == 10) { //10 tries to restore connection 
                clearInterval(idnttyNodeHeartbeat);
            } else {
                this.idnttyNodeHeardbeat = 0;
            }
          }, 30000); //30 sec between tries
    }

    unload() {        
        this.idnttyNodeClient.disconnect();
    }

    online() {        
        this.idnttyNodeClient.invoke('idnttyvpn:tunnelAdd', {
            publicKey: this.idnttyPublicKey.toString('hex'),
            serverAddress: this.publicAddress, 
            serverPort: this.publicPort,
            serverSubnet: this.privateSubnet,            
            county: this.county,
            region: this.region
        }).then( async _idnttyNode => {
                this.idnttyNodePublicKey = _idnttyNode.publicKey;                
                console.log(_idnttyNode);
        });
    }

    ping() {
        const now = Date.now();
        let self = this;

        //get current wg peers
        let wgPeers = [];
        Wg.show(this.interface).then(async function(_interface) {            
            Object.keys(_interface[self.interface]['_peers']).forEach((_peer) => {
                let peer = {
                    wgPublicKey: _peer,                                                            
                    transferRx: _interface[self.interface]['_peers'][_peer]["_transferRx"],
                    transferTx: _interface[self.interface]['_peers'][_peer]["_transferTx"],
                };
                wgPeers.push(peer);
                console.log(peer);
            });                             
        });

        
        let idnttyPeers = [];
        this.peers.forEach((_peer) => {
            if (_peer.publicKey != null){
                wgPeers.forEach((_wgPeer) =>{
                    if (_peer.wgPublicKey == _wgPeer.wgPublicKey) {
                        let _transferRx = _wgPeer.transferRx - _peer.transferRx;
                        let _transferTx = _wgPeer.transferTx - _peer.transferTx;
                        idnttyPeers.push({ peer:_peer.publicKey, transferRx: _transferRx, transferTx:_transferTx, latestHandshake: _peer.latestHandshake });
                    }
                })
            }            
        });

        this.idnttyNodeClient.invoke('idnttyvpn:tunnelUpdateStatus', {
            publicKey: this.idnttyPublicKey.toString('hex'), 
            peers: idnttyPeers
        }).then( async _idnttyNode => {
            console.log(_idnttyNode);
        });   
    }

    calculateNextIp() {
        let _privateSubnet = new Netmask(this.privateSubnet);

        let peersIP = [];
        this.peers.forEach((_peer) => {            
            let peerIP = _peer.allowedIps[0].substring(0, _peer.allowedIps[0].indexOf("/"));            
            let peerIPnumber = peerIP.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
            peersIP.push(peerIPnumber);
        });

        if (peersIP.length >= _privateSubnet.size) { return null; }

        let IPnumber = _privateSubnet.first.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
        for (let i = 1; i<_privateSubnet.size; i++) { //first reserved for the gateway
            IPnumber = IPnumber + i;
            if (!peersIP.includes(IPnumber)) { return ( (IPnumber>>>24) +'.' + (IPnumber>>16 & 255) +'.' + (IPnumber>>8 & 255) +'.' + (IPnumber & 255) ); }
        }

        return null;
    }

    removeVPNPeer(clientPublicKey) {
        //convert from idntty PK to WG PK
        let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
        sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, Buffer.from(clientPublicKey, 'hex'));  
        let wgPublicKey = x25519_pk.toString('Base64');

        exec(`sudo wg set ${this.interface} peer ${wgPublicKey} remove`, (error, stdout, stderr) => {
            if (error) { return false; }
            if (stderr) { return false; }

            for( var i = 0; i < this.peers.length; i++){ 
                if ( this.peers[i].publicKey === clientPublicKey) { this.peers.splice(i, 1); }
            }
            return true;
        });
    }

    addVPNPeer(clientPublicKey, allowedIP) {
        //convert from idntty PK to WG PK
        let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
        sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, Buffer.from(clientPublicKey, 'hex'));
        let wgPublicKey = x25519_pk.toString('Base64');

        exec(`sudo wg set ${this.interface} peer ${wgPublicKey} allowed-ips ${allowedIP}`, (error, stdout, stderr) => {
            if (error) {
                console.log("error:", error);
                return false; }
            if (stderr) { 
                console.log("stderr:", stderr);
                return false; 
            }

            let peer = {
                publicKey: clientPublicKey,
                wgPublicKey: x25519_pk.toString('Base64'),
                endpoint: null,
                allowedIps: [allowedIP],
                latestHandshake: null,
                transferRx: 0,
                transferTx: 0,
            };
            this.peers.push(peer);
            
            let _peer = {
                tunnelPublicKey: this.idnttyPublicKey,
                publicKey: clientPublicKey,
                state: 1,
                address: allowedIP
              }

            this.idnttyNodeClient.invoke('idnttyvpn:peerConfirm', _peer);
            return true;
        });
    }

    updatePublicIP() {
        http.get({'host': 'api.ipify.org', 'port': 80, 'path': '/'}, function(resp) {
            resp.on('data', function(ip) {
                this.publicAddress = ip;
            });
        });
    }

    updateVPNSettings() {
        let self = this;
        Wg.show(this.interface).then(async function(_interface) {
            self.publicPort = _interface[self.interface]['_listenPort'];
            self.idnttyPublicKey = _interface[self.interface]['_publicKey'];
        });
    }

    async updateVPNPeers() {
        let self = this;
        Wg.show(this.interface).then(async function(_interface) {
            self.peers = [];
            Object.keys(_interface[self.interface]['_peers']).forEach((_peer) => {
                let peer = {
                    wgPublicKey: _peer,
                    endpoint: _interface[self.interface]['_peers'][_peer]["_endpoint"],
                    allowedIps: _interface[self.interface]['_peers'][_peer]["_allowedIps"],
                    latestHandshake: _interface[self.interface]['_peers'][_peer]["_latestHandshake"],
                    transferRx: _interface[self.interface]['_peers'][_peer]["_transferRx"],
                    transferTx: _interface[self.interface]['_peers'][_peer]["_transferTx"],
                };
                self.peers.push(peer);
		        console.log(peer);
            });                             
        });
    }

}


let vpn = new IdnttyVPNServer();
vpn._load();