const serverPackage = require('./package.json');

const { codec } = require('lisk-sdk');
const { exec } = require("child_process");
const { Wg } = require('wireguard-wrapper');
const { apiClient } = require('@liskhq/lisk-client');
var http = require('http');


class IdnttyVPNServer {

    idnttyPublicKey = null;
    idnttyEndtpoint = null;
    idnttyNodeClient = null;
        
    interface = null;
    publicKey = null;    
    publicAddress = null;
    publicPort = null;
    addressRange = null;
    vpnHeardbeat = 0;

    peers = [];

    constructor() {    
        this.idnttyPublicKey = serverPackage.idnttyPublicKey;
        this.idnttyEndtpoint = serverPackage.idnttyEndtpoint;        

        this.interface = serverPackage.interface;
        this.publicKey = serverPackage.publicKey;
        this.publicAddress = serverPackage.publicAddress;
        this.publicPort = serverPackage.publicPort;
        this.addressRange = serverPackage.addressRange;   
        this.peers = [];
    }

    load() {        
        apiClient.createWSClient(this.idnttyEndtpoint).then(async _client => {
            this.idnttyNodeClient = _client;
            await this.updateVPNPeers();            

            this.idnttyNodeClient.subscribe('idnttyvpn:peeradd', (peer) => {

                let allowedIP = this.calculateNextIp();
                let addpeerresult = this.addVPNPeer(peer.publicKey, allowedIP.concat("/32"));

                this.idnttyNodeClient.invoke('idnttyvpn:peer', { publicKey : peer.publicKey, ip: allowedIP });
                console.log("newPeer:", addpeerresult, allowedIP, peer.publicKey);
            });  
            
            this.idnttyNodeClient.subscribe('app:block:new', (data) => { //Ping every 10 blocks
                this.vpnHeardbeat++;
                if (this.vpnHeardbeat > 9) {
                    this.ping();
                    this.vpnHeardbeat = 0;
                }                
            }); 
            
        });
    }

    unload() {        
        this.idnttyNodeClient.disconnect();
    }

    ping() {
        const now = Date.now();
        
        let peersCount = 0;
        let totalTransferRx = 0;
        let totalTransferTx = 0;

        this.peers.forEach((_peer) => {            
            if ((now - _peer.latestHandshake*1000) < 24*60*60*1000) { peersCount++; } //Count active peers last 24 hours
            totalTransferRx = totalTransferRx + _peer.transferRx;
            totalTransferTx = totalTransferTx + _peer.transferTx;
        });

        this.idnttyNodeClient.invoke('idnttyvpn:servers').then( async _servers => {
            console.log(peersCount, totalTransferRx, totalTransferTx);
            console.log(_servers);
        });   
    }

    calculateNextIp() {        
        let lowIPnumber = this.addressRange.low.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
        let highIPnumber = this.addressRange.high.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;

        let peersIP = [];
        this.peers.forEach((_peer) => {            
            let peerIP = _peer.allowedIps[0].substring(0, _peer.allowedIps[0].indexOf("/"));            
            let peerIPnumber = peerIP.split('.').reduce(function(ipInt, octet) { return (ipInt<<8) + parseInt(octet, 10)}, 0) >>> 0;
            peersIP.push(peerIPnumber);            
        });

        console.log(peersIP);

        for (let newIP = lowIPnumber; newIP < highIPnumber; newIP++) {
            if (!peersIP.includes(newIP)) {
                console.log(newIP);
                console.log((newIP>>>24) +'.' + (newIP>>16 & 255) +'.' + (newIP>>8 & 255) +'.' + (newIP & 255));
                return ( (newIP>>>24) +'.' + (newIP>>16 & 255) +'.' + (newIP>>8 & 255) +'.' + (newIP & 255) );
            }
        }

        return null;        
    }

    removeVPNPeer(clientPublicKey) {
        exec(`sudo wg set ${this.interface} peer ${clientPublicKey} remove`, (error, stdout, stderr) => {
            if (error) { return false; }
            if (stderr) { return false; }

            for( var i = 0; i < this.peers.length; i++){ 
                if ( this.peers[i].publicKey === clientPublicKey) { this.peers.splice(i, 1); }
            }
            return true;
        });
    }

    addVPNPeer(clientPublicKey, allowedIP) {
        exec(`sudo wg set ${this.interface} peer ${clientPublicKey} allowed-ips ${allowedIP}`, (error, stdout, stderr) => {
            if (error) {
                console.log("error:", error);
                return false; }
            if (stderr) { 
                console.log("stderr:", stderr);
                return false; 
            }

            
            
            let peer = {
                publicKey: clientPublicKey,
                endpoint: null,
                allowedIps: allowedIP,
                latestHandshake: null,
                transferRx: null,
                transferTx: null,
            };
            this.peers.push(peer);
            console.log("addVPNPeer - ok");
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
                    publicKey: _peer,
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
vpn.load();
let allowedIP = vpn.calculateNextIp();
let addpeerresult = vpn.addVPNPeer("uDN6Wb4imyX1DBRV1/v+CbuZy9HZbFYIuayNVl/YFF8=", allowedIP.concat("/32"));

//setTimeout(function() { vpn.unload() }, 25000);
