const serverPackage = require('./settings.json');
const fs = require('fs')
const { codec } = require('lisk-sdk');
const { Wg } = require('wireguard-wrapper');
const { apiClient } = require('@liskhq/lisk-client');
const Netmask = require('netmask').Netmask;
const { getPrivateAndPublicKeyFromPassphrase } = require('@liskhq/lisk-cryptography');
var sodium = require('sodium-native');
var http = require('http');
const {exec, execSync} = require('child_process');

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
        this.county = serverPackage.county;
        this.region = serverPackage.region;        
    }


    async _load() {
        this._syncPeers();

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
            this.idnttyNodePublicKey = _idnttyNode.publicKey;
            this._tunnelHeartbeat();
        });
    }

    async _tunnelStatus() {        
        let _tunnel = {
            publicKey: this.idnttyPublicKey.toString('hex'),
            transferRx: 0,
            transferTx: 0,
            peers:[]
        }

        await this._syncPeers();
        this.peers.forEach(idnntyPeer => {
            if (idnntyPeer.hasOwnProperty('publicKey')) {
                let peer = {
                    address: idnntyPeer.allowedIps,
                    publicKey: idnntyPeer.publicKey,
                    latestHandshake: idnntyPeer.latestHandshake,
                    transferRx: idnntyPeer._transferRx,
                    transferTx: idnntyPeer._transferTx
                };

                _tunnel.transferRx = _tunnel.transferRx + idnntyPeer._transferRx;
                _tunnel.transferTx = _tunnel.transferTx + idnntyPeer._transferTx;

                _tunnel.peers.push(peer);
            }
        });

        this.idnttyNodeClient.invoke('idnttyvpn:tunnelUpdateStatus', _tunnel)
        .then( async _idnttyNode => {
            console.log("DEBUG:", "_tunnelStatus", _tunnel.publicKey);
        });   
    }

    async _tunnelHeartbeat() {        
        let idnttyNodeHeartbeat = setInterval(async () => {
            console.log("DEBUG:", "_tunnelHeartbeat", this.idnttyNodeClient._channel.isAlive,  this.idnttyNodeHeardbeat);            
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
        //convert from idntty PK to WG PK
        let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
        sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, Buffer.from(clientPublicKey, 'hex'));
        let wgPublicKey = x25519_pk.toString('Base64');

        //Tunnel info
        const tunnelPublicKey = this.idnttyPublicKey.toString('hex');
        const interfaceName = this.interface;

        //check if exist
        let exist = false;
        let peer = {};
        this.peers.forEach(idnntyPeer => {
            if (idnntyPeer.publicKey ===  clientPublicKey || idnntyPeer.wgPublicKey ===  wgPublicKey) {                 
                peer = (({ transferRx, transferTx, allowedIps, latestHandshake }) => ({ transferRx, transferTx, allowedIps, latestHandshake }))(idnntyPeer);
                peer.publicKey = clientPublicKey;
                peer.tunnelPublicKey = tunnelPublicKey;
                idnntyPeer.publicKey = clientPublicKey;

                exist = true;
            }
        });

        if (exist) {
            this.idnttyNodeClient.invoke('idnttyvpn:peerConfirm', peer);
            console.log("DEBUG:", "_peerAdd (duplicate)", clientPublicKey, peer.allowedIps);
            return true;
        }

        //get ip for new peer
        let peerIp = this._calculatePeerIP();
        if (peerIp == null) { return false; }
                
        peerIp = peerIp.concat("/32");

        peer = {
            publicKey: clientPublicKey,
            wgPublicKey: x25519_pk.toString('Base64'),
            endpoint: null,
            allowedIps: peerIp,
            latestHandshake: null,
            transferRx: 0,
            transferTx: 0,
        };
        this.peers.push(peer);

        return new Promise(function(resolve, reject){
			execSync(`sudo wg set ${interfaceName} peer ${wgPublicKey} allowed-ips ${peerIp}`, function(error, stdout, stderr){
				if(error || stderr){
					return reject(`DEBUG: _peerAdd error ${error}, ${stderr}`);                    
				}
				resolve({
                    tunnelPublicKey: tunnelPublicKey,
                    publicKey: clientPublicKey,
                    state: 1,
                    address: peerIp
                });
			});
		}).then(async (_peer) => {
            this.idnttyNodeClient.invoke('idnttyvpn:peerConfirm', _peer);            
        });

    }

    async _peerRemove(clientPublicKey) {        
        const interfaceName = this.interface;

        //convert from idntty PK to WG PK
        let x25519_pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
        sodium.crypto_sign_ed25519_pk_to_curve25519(x25519_pk, Buffer.from(clientPublicKey, 'hex'));  
        let wgPublicKey = x25519_pk.toString('Base64');

        return new Promise(function(resolve, reject){
			execSync(`sudo wg set ${interfaceName} peer ${wgPublicKey} remove`, function(error, stdout, stderr){
				if(error || stderr){
					return reject(`DEBUG: _peerRemove error ${error}, ${stderr}`);                    
				}
			});
		}).then(() => {            
            console.log("DEBUG:", "_peerRemove", clientPublicKey);
            for( var i = 0; i < this.peers.length; i++){ if ( this.peers[i].publicKey === clientPublicKey) { this.peers.splice(i, 1); } }
        });
    }    

    /* Utils */
    _calculatePeerIP() {
        let _privateSubnet = new Netmask(this.privateSubnet);

        let peersIP = [];
        this.peers.forEach((_peer) => {                        
            let peerIP = _peer.allowedIps.substring(0, _peer.allowedIps.indexOf("/"));
            let peerIPnumber = peerIP.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
            peersIP.push(peerIPnumber);
        });
        
        if (peersIP.length >= _privateSubnet.size) { return null; }

        let _ip = _privateSubnet.first.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
        for (let ip = _ip + 1; ip<_privateSubnet.size + _ip + 1; ip++) { //first reserved for the gateway           
            if (!peersIP.includes(ip)) {
                console.log("DEBUG:", "_calculatePeerIP new IPnumber:", ip);
                return ( (ip>>>24) +'.' + (ip>>16 & 255) +'.' + (ip>>8 & 255) +'.' + (ip & 255) ); 
            }
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

    async _syncPeers(){
        const vpnPeers = await this._getVPNPeers();
        
        vpnPeers.forEach(wgPeer => {
            let exist = false;
            this.peers.forEach(idnntyPeer => {
                if (idnntyPeer.wgPublicKey == wgPeer.wgPublicKey) {

                    idnntyPeer._transferRx = wgPeer.transferRx - idnntyPeer.transferRx;
                    idnntyPeer._transferTx = wgPeer.transferTx - idnntyPeer.transferTx;

                    idnntyPeer.transferRx = wgPeer.transferRx;
                    idnntyPeer.transferTx = wgPeer.transferTx;

                    idnntyPeer.latestHandshake = wgPeer.latestHandshake;
                    idnntyPeer.allowedIps = wgPeer.allowedIps;

                    exist = true;
                }
            });    
            if (!exist && wgPeer.allowedIps != '(none)') {  this.peers.push(wgPeer); }                        
        });
        console.log("DEBUG:", "_syncPeers", this.peers.length);
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

}


let vpn = new IdnttyVPNServer();
vpn._load();